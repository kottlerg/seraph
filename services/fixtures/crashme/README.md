# crashme

Test fixture that dies on a fault on purpose, for the crash report its death leaves in the system
log.

---

## Role

svctest drives the fixture through the `crashd_faults`, `crashd_cores`, `crashd_live_core`, and
`crashd_oom_hold` phases (§ Driven By), through its `crash_endpoint` phase, in the `vm`,
`exception`, `registry-main`, `registry-worker`, and `debugger-tag` modes, through its `oom_policy`
phase, in the `oom-touch` mode with 1024 pages, and, through the [`leader`](../leader/README.md)
fixture of an operator session it opens, in the `oom-hold` mode ([services/svctest/README.md §
Fixtures](../../svctest/README.md#fixtures)). The fixture installs at
`/tests/fixtures/programs/crashme`.

| Mode | Fault |
|---|---|
| `vm` | A write to the null page: a page fault memmgr cannot back, which it forwards to the crash endpoint |
| `exception` | An illegal instruction (`ud2` on x86-64, `unimp` on riscv64) |
| `worker` | The illegal instruction on a spawned thread, listed past the first page of an attach (after four parked threads), while a sibling is held blocked on a fault at the same instruction: the main thread binds the sibling's exception class to its own endpoint, and a holder thread receives that fault and never answers it |
| `registry-main` | The illegal instruction on the main thread, with two parked threads registered and a detached one exited |
| `registry-worker` | The illegal instruction on a spawned thread, after its registered sibling was joined |
| `debugger-tag` | None: in steps svctest sets up as its debugger, each let go by a line on stdin, it checks that a thread it spawns while its main thread carries a debugger's binding, with no debugger watched, is bound back to the crash endpoint under a crash badge and its upcall class unbound at its registration, then that its `DECLARE_NO_DEBUG`, with a debugger attached and watched, unbinds the debugger's exception and upcall bindings of its main thread; it prints one line per step and exits 0 when both hold |
| `oom-touch <pages>` | A write to each page of a demand region of `<pages>` pages it registered before, in turn, made on its second line of stdin while the `oom-fill` mode or the `memhog` fixture keeps memory critical: the writes spend whatever free pages lie above the growth floor (the system reserve and, while pages are swapped, the restore headroom), and memmgr declines the first past them for want of memory, which the crash service holds. It prints `ready` after the first line, and `touched held_ms=<ms>`, its longest write, and exits 0 when the writes complete; it dies of the fault when the hold times out |
| `oom-fill <ms>` | None: through [`mem-fill`](../../../shared/mem-fill/README.md), shared with the `memhog` fixture, it commits what memmgr can still promise a process outside the system reserve, through its heap and then by one-page grants, until nothing is left and the pressure level has read `CRITICAL` for 500 ms, prints `full`, keeps taking what other processes free for `<ms>` milliseconds, and exits 0, which gives it all back |
| `oom-hold <pages>` | None: it touches `<pages>` pages of heap, prints `holding <pages>`, and waits to be destroyed: a job of an operator session, which oomd stops before any service ([docs/session-supervision.md](../../../docs/session-supervision.md)) |
| `registry-declare` | None: with a registered thread parked, it sends `DECLARE_NO_DEBUG` and checks that the thread's crash binding, under a badge other than the main thread's, is unbound with the main thread's; it prints `registry-declare: PASS` and exits 0 when so |
| `live` | None: it parks two registered threads, fills 4096 bytes of its heap with a known word, prints `ready mark=<address>`, and waits for a line on stdin while the crash service writes a live core of it; it then checks that its threads are still parked and the bytes still hold the word, prints `live: PASS` or `live: FAIL`, and exits 0 when both hold |
| `live-no-core` | None: it declares itself on the core path (`DECLARE_NO_CORE`), prints `ready`, waits for a line on stdin, and exits 0; it exits 1 when procmgr refuses the declaration |

In each faulting mode the fixture registers the log name `crashme` and logs a line first, so logd's
`reclaim:` line at its death names it, and prints `faulting (<mode>)` to stdout. It reaches the
fault two calls deep, so the report's stack walk has frames to find. The threads it spawns
register with procmgr ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread
registration), so the crash service reads a spawned thread's fault as it reads the main thread's.
The `oom-` modes register the log name `crashme-oom` instead, so the crash-report check, which
reads the `crashme` blocks, does not take the timed-out fault's block for one of them. Neither
`oom-fill` nor `oom-touch` allocates nor touches a new stack page between the filler's `full` and
its exit, since a fault of its own would be held too.

---

## Driven By

The phases live in `services/svctest/src/phases/crashd.rs`. The staged crash service's recipe,
`rootfs/config/svcmgr/tests/crashd.svc`, sets `CORE_DUMP` to `crashme`
([docs/testing.md](../../../docs/testing.md) § Gating), so each faulting death leaves an ELF core
([services/crashd/docs/core-format.md](../../crashd/docs/core-format.md)). The report blocks
themselves are checked host-side, in the boot's serial log, by `cargo xtask run --crash-reports`
([docs/testing.md](../../../docs/testing.md) § Crash reports), which ties each block to `crashme`
through the badge logd's `reclaim:` line names.

### `crashd_faults`

For each of `vm`, `exception`, and `worker`, in that order, it spawns
`/tests/fixtures/programs/crashme <mode>` with a piped stdout, reads stdout to EOF, and waits. It
asserts:

- stdout contains `faulting (<mode>)`;
- the exit is not a success;
- the exit reason is in the fault range, `0x1000` up to but not including `0x2000`;
- exactly one core ending `-crashme.core` is new in `/crash` since before the spawn; the phase
  records its name for `crashd_cores`.

It then runs `registry-declare` and asserts that the exit is a success and stdout contains
`registry-declare: PASS`.

### `crashd_cores`

It asserts that `crashd_faults` recorded at least one core, then reads each recorded core with a
reader of its own, not crashd's code, and asserts that it is:

- a 64-bit little-endian ELF file of type `ET_CORE` and of this machine, with a `PT_NOTE`;
- carrying a first `NT_PRSTATUS` whose signal is `SIGSEGV` for `vm` and `SIGILL` for the others;
- with an instruction pointer inside a `PT_LOAD` whose bytes the core holds, and, in the
  `exception` and `worker` modes, the illegal instruction (`ud2` on x86-64, `unimp` on riscv64)
  at those bytes;
- with a stack pointer inside a `PT_LOAD` whose bytes the core holds;
- and, for `worker`, with more than one `NT_PRSTATUS`.

### `crashd_live_core`

It asserts that svctest holds the `crashd.core` bootstrap capability, then asks the crash service
for live cores ([services/crashd/docs/operation.md](../../crashd/docs/operation.md) § Live Core),
each charged to a copy of its own memmgr account.

For `crashme live`: the fixture prints `ready mark=0x<address>` (otherwise it panics); the
`LIVE_CORE` reply is `SUCCESS`; after the phase writes `check` to the fixture's stdin, the
fixture exits with a success and prints `live: PASS`, so it ran on unchanged; exactly one core is
new in `/crash`, its name starting with the reply's sequence number and its length equal to the
reply's byte count; and the core is an `ET_CORE` of this machine holding at least three
`NT_PRSTATUS` notes, each of signal 0, each stack pointer inside a written `PT_LOAD`, the main
thread's instruction pointer, in the binary's text, inside no `PT_LOAD` (so a debugger reads the
text from the binary), and every 8-byte word of the 4096 marked bytes inside a written `PT_LOAD` and
equal to the mark word `0x4c49_5645_434f_5245`.

For `crashme live-no-core`: the fixture prints `ready`; the `LIVE_CORE` reply is `NO_CORE`; the
pages charged to the phase's account (`QUERY_MEMORY_USAGE`) are the same after the reply as before
the request, so the refused capture was released; after the phase writes `exit` to its stdin the
fixture exits with a success; and no core is new in `/crash`.

### `crashd_oom_hold`

It runs after the swap phases and checks the crash service's hold of a fault declined for want of
memory ([services/crashd/docs/operation.md](../../crashd/docs/operation.md) § Hold). The stall it
uses is the one the staged crash service's recipe sets, read from the recipe. In each of two cases
it starts `oom-touch 1024`, waits for its `ready`, touches 16 KiB of its own stack so its window
faults no new stack page, starts `oom-fill <ms>` and waits for `full`, and tells the fixture to
write. Either fixture still running 30 s after it was waited on (30 s and the stall for the timeout
case's `oom-touch`) is killed and the phase panics.

- Resume: the filler keeps memory critical for 1000 ms after `full`. It asserts that the filler
  exits with a success, that the fixture exits with a success, and that its line is `touched
  held_ms=<ms>` with at least 500 ms.
- Timeout: the filler keeps memory critical until the fixture has died, and the phase then kills it,
  since an oomd stop that frees memory ends the hold it finds and the fixture's next write is held
  anew. It asserts that the filler was still running when the fixture died; that the fixture does
  not exit with a success, its exit reason is in the fault range, and it died at least the stall
  after it was told to write; and that no core is new in `/crash`, since memory was still critical.

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
```

---

## Relevant Design Documents

| Document | Covers |
|---|---|
| [services/crashd/README.md](../../crashd/README.md) | The crash service the fixture's deaths are reported by |
| [services/crashd/docs/core-format.md](../../crashd/docs/core-format.md) | The core the phases check |
| [services/crashd/docs/operation.md](../../crashd/docs/operation.md) | § Hold: the hold the `oom-` modes drive; § Live Core: the live cores the phases ask for |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | § Crash Reports, § Reply |
| [docs/testing.md](../../../docs/testing.md) | § Gating, § Crash reports |

---

## Summarized By

None