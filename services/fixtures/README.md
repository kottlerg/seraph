# fixtures

The test fixtures: the binaries the harnesses (`svctest`, `usertest`, `ubench`) spawn, and that no
other process runs. Each is a test feature
([docs/testing.md](../../docs/testing.md) § Sysroot layout): it installs under
`/tests/fixtures/` and reaches a disk image only through a harness's staging.

Where a fixture installs sets the signing role it is signed under
([docs/signing.md](../../docs/signing.md)):

- A fixture a harness spawns as a program installs at
  `/tests/fixtures/programs/<name>`, whose `programs` component gives it the program role, the
  role of a process a program may start.
- A fixture a harness recipe starts as a service installs at `/tests/fixtures/<name>`, with the
  service role. Its recipe is under `/config/svcmgr/tests/` and is staged only by the harness
  that runs it.

A fixture has no tester crate of its own: the harness that spawns it runs its checks, as a phase of
`svctest` ([services/svctest/README.md](../svctest/README.md)).

---

## Program fixtures

Installed at `/tests/fixtures/programs/<name>`.

| Crate | Purpose |
|---|---|
| [`program-modes/`](program-modes/README.md) | svctest's shared program-role fixture: the `capexhaust`, `deadline`, `demandpaged`, `narrow`, `pipefault`, `pipestress`, `relrofault`, `stackoverflow`, `threadchurn` and `threadstack` modes |
| [`crashme/`](crashme/README.md) | Deliberate-fault fixture for the svctest `crashd` phases and the crash-report check |
| [`debugger/`](debugger/README.md) | Debugger fixture for the svctest `debugger` phase: breakpoint, single-step, memory inspection, and async break |
| [`fsbench/`](fsbench/README.md) | `std::fs::File` read and write benchmark: the `FS_READ` vs `FS_READ_MEMORY` crossover, and `FS_WRITE_MEMORY` rewrites |
| [`leader/`](leader/README.md) | Session leader of svctest's operator sessions: a line-oriented command loop standing in for the shell |
| [`spawn-target/`](spawn-target/README.md) | Known-good program-role image the svctest phases create, spawn, read, and look up |
| [`stdiotest/`](stdiotest/README.md) | Stdin↔stdout proof |

The other program fixtures keep a binary of their own, each for a reason the shared one cannot meet:

- `spawn-target`: its image is the subject of procmgr's create, read and lookup checks, and its
  name that of the `ns` phase's LFN lookups.
- `leader`: sessiond's recipe names it, and sessiond starts it with no argument.
- `crashme`: its name is what the crash-report check, crashd's `CORE_DUMP` list and the symbolizer
  key on.
- `debugger`, `fsbench` and `stdiotest`: another harness runs them too, as the debug-port case's
  `gdb-target` recipe, `ubench` and `usertest`'s shell tester do.
- `debug-echo` and `hotplug-check` (service role): the debug-port and hotplug cases run them, and
  their directories name the device surfaces of [docs/testing.md](../../docs/testing.md).

## Service fixtures

Installed at `/tests/fixtures/<name>`.

| Crate | Purpose |
|---|---|
| [`service-modes/`](service-modes/README.md) | svctest's shared service-role fixture: the `crasher`, `memhog` and `stopsrc` modes |
| [`debug-echo/`](debug-echo/README.md) | Answers fixed GDB remote serial protocol packets on the debug port |
| [`hotplug-check/`](hotplug-check/README.md) | Checks that devmgr binds a driver to a device hot-added behind a PCI Express root port, and that its DMA and MSI work; its disk mode checks vfsd's handling of a disk removed and added again, and of its root driver's loss |

---

## Summarized By

None
