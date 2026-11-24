# fixtures

The test fixtures: the binaries the harnesses (`svctest`, `usertest`, `ubench`) and the
per-program testers spawn, and that no other process runs. Each is a test feature
([docs/testing.md](../../docs/testing.md) § Sysroot layout): it installs under `/tests/fixtures/`
and reaches a disk image only through a harness's staging.

Where a fixture installs sets the signing role it is signed under
([docs/signing.md](../../docs/signing.md)):

- A fixture a harness or a tester spawns as a program installs at
  `/tests/fixtures/programs/<name>`, whose `programs` component gives it the program role, the
  role of a process a program may start.
- A fixture a harness recipe starts as a service installs at `/tests/fixtures/<name>`, with the
  service role. Its recipe is under `/config/svcmgr/tests/` and is staged only by the harness
  that runs it.

A fixture's tester, when it has one, is the fixture's `tester/` crate, installed at
`/tests/programs/<name>` and run by `usertest`
([programs/usertest/README.md](../../programs/usertest/README.md) § Testers).

---

## Program fixtures

Installed at `/tests/fixtures/programs/<name>`.

| Crate | Purpose |
|---|---|
| [`capexhaust/`](capexhaust/README.md) | CSpace-exhaustion fixture for the recv-wedge regression test |
| [`crashme/`](crashme/README.md) | Deliberate-fault fixture for the usertest `crashme` tester and the crash-report check |
| [`deadline/`](deadline/README.md) | Deadline-cancel fixture for the usertest `deadline` tester: an upcall cancels a spinning worker |
| [`debugger/`](debugger/README.md) | Debugger fixture for the usertest `debugger` tester: breakpoint, single-step, memory inspection, and async break |
| [`demandpaged/`](demandpaged/README.md) | Demand-paging fixture for the svctest pager phase |
| [`fsbench/`](fsbench/README.md) | `std::fs::File` read and write benchmark: the `FS_READ` vs `FS_READ_MEMORY` crossover, and `FS_WRITE_MEMORY` rewrites |
| [`pipefault/`](pipefault/README.md) | Piped-stdio fault fixture for the pipe death-bridge regression test |
| [`pipestress/`](pipestress/README.md) | Spawn-exit-drain stress fixture for the pipe EOF-drain regression test |
| [`relrofault/`](relrofault/README.md) | RELRO write fixture for the `PT_GNU_RELRO` enforcement test |
| [`stackoverflow/`](stackoverflow/README.md) | Stack-overflow fixture for the stack guard-page regression test |
| [`stdiotest/`](stdiotest/README.md) | Stdin↔stdout proof |
| [`threadchurn/`](threadchurn/README.md) | CSpace-slot and memmgr-pool reclaim fixture for the usertest `threadchurn` tester |
| [`threadstack/`](threadstack/README.md) | Guarded thread-stack fixture, demand-paged and pinned, for the usertest `threadstack` tester |

## Service fixtures

Installed at `/tests/fixtures/<name>`.

| Crate | Purpose |
|---|---|
| [`crasher/`](crasher/README.md) | Deliberate-crash canary for svcmgr's restart path |
| [`memhog/`](memhog/README.md) | Fills memory until the pressure level reads `CRITICAL`, for oomd to stop |
| [`stopsrc/`](stopsrc/README.md) | A stop source of the program class, whose one job oomd stops before any service |
| [`debug-echo/`](debug-echo/README.md) | Answers fixed GDB remote serial protocol packets on the debug port |
| [`hotplug-check/`](hotplug-check/README.md) | Checks that devmgr binds a driver to a device hot-added behind a PCI Express root port, and that its DMA and MSI work; its disk mode checks vfsd's handling of a disk removed and added again, and of its root driver's loss |

---

## Summarized By

None
