# threadstack

Test fixture for the guarded stack that a spawned thread gets, demand-paged or, in a process with
no pager, mapped at spawn, and for the demand growth of the main thread's stack.

---

## Role

The fixture's per-program tester, `threadstack-tester`, drives it in ten modes, and the
`usertest` orchestrator discovers and runs that tester. The fixture installs at
`/programs/threadstack` and the tester at `/tests/programs/threadstack`, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).
Both use idiomatic `std` only and handle no Seraph capabilities directly.

---

## Source Layout

```
threadstack/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # grow, nested-grow, guard, bigframe, splitframe, span, main-grow,
│                          #   main-guard, eager-grow, and eager-bigframe modes; the
│                          #   stack-growing recursion and descent
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Spawns each mode and checks stdout and exit status
```

---

## Stack Under Test

Every process procmgr creates is demand-paged by default
([Fault Handling § Default System Pager](../../docs/fault-handling.md#default-system-pager)),
so the fixture needs no opt-in: each thread it spawns gets the stack that
[ruststd § Spawned-thread stacks](../../runtime/ruststd/README.md#spawned-thread-stacks)
specifies, a demand-paged region above an unregistered guard of four pages
(`process_abi::STACK_GUARD_PAGES`) that `join` frees through
memmgr's
[`UNREGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-9-unregister_region).
Its main thread's stack is the 8 pages the loader commits (the fixture declares no stack note)
above a demand-growth range that reaches 512 pages, with an unregistered guard of at least four
pages below it, as
[docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs](../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas)
specifies.

The tester also spawns the fixture pinned (`std::os::seraph::process::CommandExt::pinned`), with no
pager. Each thread it spawns then gets the eager stack that the same section specifies: the pages
the spawn asks for, mapped at spawn, above an unmapped guard of the same four pages, all of which
`join` returns. The `guard`, `bigframe`, `eager-grow`, and `eager-bigframe` workers ask for
16 pages (`EAGER_STACK_PAGES`, std's default minimum); a demand-paged process raises that to its
512-page demand stack, and a pinned one maps exactly those 16 pages.

In `grow`, `nested-grow`, `eager-grow`, and `guard`, the worker thread recurses through `recurse`,
and each level fills and sums a 4096-byte stack buffer, so the stack grows by about one page per
level. The recursive call goes through a `black_box`'d function pointer so the optimiser cannot
fold the recursion into a loop. `main-grow` and `main-guard` run the same recursion on the main
thread. `bigframe` and `eager-bigframe` use one oversized frame instead, and `splitframe` and
`span` a descent to the bottom of the stack, as § Modes describes.

---

## Modes

The mode is the first of `main-guard`, `main-grow`, `guard`, `eager-bigframe`, `eager-grow`,
`bigframe`, `splitframe`, `span`, and `nested-grow` that some argv entry equals; otherwise it is
`grow`. A worker spawn that std refuses fails every mode's verdict: the workers of `guard`,
`bigframe`, `eager-grow`, and `eager-bigframe` print `spawn failed: <error>` and exit with code 4,
and any other refused spawn panics, which aborts the process before it prints `PASS` or
`about to overflow`.

| Mode | Behavior | Stdout and exit |
|---|---|---|
| `grow` | A worker recurses `GROW_DEPTH` (200) levels, inside the default 2 MiB usable stack, and is joined | `grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `grow worker panicked` and exits with code 3 |
| `nested-grow` | A worker spawns a second worker, which recurses `GROW_DEPTH` (200) levels and is joined by the first, which is joined in turn. The second worker's spawn copies the first worker's bindings ([Fault Handling § Inheritance is userspace policy](../../docs/fault-handling.md#inheritance-is-userspace-policy)), so the mode runs the copy from a spawned thread; both workers and the main thread carry the same pager binding, so a pass shows the second worker's demand stack is served, not which thread's binding was copied | `nested-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `nested-grow worker panicked` and exits with code 3 |
| `guard` | The main thread prints and flushes `about to overflow`, then a worker recurses without bound into the guard | No clean exit: the guard fault is terminal and procmgr tears down the whole process. If `join` returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the tester fails |
| `main-grow` | The main thread recurses `GROW_DEPTH` (200) levels, 25 times its 8 committed pages and inside its 512-page stack | `main-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS` |
| `main-guard` | The main thread prints and flushes `about to overflow`, then recurses without bound through its demand-growth range into the guard below it | No clean exit: the guard fault is terminal and procmgr tears down the whole process. If the recursion returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the tester fails |
| `bigframe` | The main thread prints and flushes `about to overflow`, spawns a worker that signals it is running and then blocks on a channel, and waits for that signal, so the top of the worker's stack and the page table covering it are mapped. A second worker, whose stack the reservation arena places directly above the first worker's one-page IPC buffer, itself directly above the first worker's stack, calls a function with one frame of 519 pages (the 512-page default usable stack, its 4-page guard, and 3 pages) and writes only the frame's lowest byte, which lies past the guard and that IPC buffer, near the top of the first worker's registered stack. Only the stack probes that [ruststd § Spawned-thread stacks](../../runtime/ruststd/README.md#spawned-thread-stacks) describes reach the guard | No clean exit: the probe faults on the guard and procmgr tears down the whole process. If `join` returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the tester fails |
| `splitframe` | The same two workers as `bigframe`. The second takes its usable base as the page boundary above its first frame less 512 pages, and descends its stack in written frames, of a page and then of 256 bytes, until its frame lies within 1024 bytes of that base. A dry run makes the descent, writes 64 bytes below it, and returns, which shows that the descent and the overflow's first write lie in the usable stack. The worker then prints and flushes `about to overflow` and descends again to call `split_frame`, a 6128-byte frame that saves its return address and calls `page_leaf`, a leaf with 4080 bytes of locals that writes only its lowest byte. On riscv64 the frame is allocated as 2032 bytes and then 4096 unprobed, so the leaf's byte lies about 10 KiB below the save with nothing written between them ([docs/build-system.md § Custom Targets](../../docs/build-system.md#custom-targets)): past a guard of two pages or fewer, on a mapped page of the first worker: its IPC buffer, or its stack below | As `bigframe`. A dry run that faults, which a misjudged base causes, prints no `about to overflow`, and the tester fails |
| `span` | As `splitframe`, but the overflow is two stores 14312 bytes apart with nothing written between them, the std target's bound on the distance between two consecutive stack stores, which `process_abi::STACK_GUARD_PAGES` covers: past a guard of three pages or fewer, on a mapped page of the first worker: its IPC buffer, or its stack below | As `splitframe` |
| `eager-grow` | For a pinned run. A worker recurses `EAGER_GROW_DEPTH` (10) levels, about 41 KiB, inside its 16-page eager stack, and is joined | `eager-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `eager-grow worker panicked` and exits with code 3 |
| `eager-bigframe` | For a pinned run. As `bigframe`, but the frame is 23 pages (the 16-page eager stack, its 4-page guard, and 3 pages), so its lowest byte lies past the guard and the parked worker's IPC buffer, near the top of the parked worker's mapped eager stack. Waiting for the parked worker changes nothing here, since an eager stack is mapped whole at spawn. A stack with no unmapped guard below it, over mapped memory, lets the frame return | As `bigframe` |

A terminal fault on a worker thread brings down the whole process because procmgr observes the
address space's death, as
[Capability Model § "Kill process" pattern](../../docs/capability-model.md#kill-process-pattern)
describes.

---

## Tester Checks

`threadstack-tester` runs `/programs/threadstack` demand-paged in the modes `grow`, `guard`,
`bigframe`, `splitframe`, `span`, `nested-grow`, `main-grow`, and `main-guard`, then pinned in
`eager-grow`, `guard`, and `eager-bigframe`, in that order, through `std::process::Command`. For
each run it pipes stdout, reads it to the end, and waits for the exit status. It fails, printing
`[threadstack-tester] FAIL <reason>` and exiting with code 1, when any of these holds (a pinned
run's reason names its mode with ` (pinned)`):

- `grow`, `nested-grow`, `main-grow`, and `eager-grow`: a stdout line is `SURVIVED (BUG)`, no line
  is `PASS`, or the exit is not a success.
- `guard`, `bigframe`, `splitframe`, `span`, `main-guard`, and `eager-bigframe`: a stdout line is
  `SURVIVED (BUG)`, no line contains `about to overflow`, the exit is a success, or the exit code
  is below `EXIT_FAULT_BASE` (`0x1000`), the base of the Fault range in
  [Process Lifecycle § Exit reason](../../docs/process-lifecycle.md#exit-reason) (so a Fault or
  Killed reason passes).

If all eleven runs pass, it prints `[threadstack-tester] PASS` and exits with code 0.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester layout, install path, and exit-code contract |
| [docs/build-system.md](../../docs/build-system.md) | The std targets' inline stack probes, and the span between two stack stores they leave on riscv64 |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Demand paging as the system default; memmgr as the pager; the fatal fault of a process with no pager |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | The main-thread stack's committed pages, demand-growth range, and guard |
| [docs/capability-model.md](../../docs/capability-model.md) | Address-space death observers and process teardown on a terminal fault |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Exit-reason ranges, including `EXIT_FAULT_BASE` |
| [runtime/ruststd/README.md](../../runtime/ruststd/README.md) | Spawned-thread stack geometry, demand and eager, and release at `join`; the main-thread growth range `_start` registers |
| [memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md) | `UNREGISTER_REGION`, which frees a joined thread's guarded stack |

---

## Summarized By

None
