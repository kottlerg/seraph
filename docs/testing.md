# Testing

System-wide standard for the in-tree test harnesses, the per-program tester
protocol, the sysroot layout for test binaries, the gating mechanism
that determines which harnesses run in a given boot, and the tools that
diagnose a failing boot.

This document covers booted functional testing, the fuzzing tier of the parsers of hostile input (§
Fuzzing), and the bounded proofs of pure, sequential code (§ Bounded verification). Host-side
`#[cfg(test)]` unit tests — their quality rules and the boundary between host-unit and booted
testing — are governed by [coding-standards.md](coding-standards.md#d-testing-invariants). `cargo
xtask test` runs them on the host and again built for riscv64 under QEMU's user-mode emulator, which
needs the packages [build-system.md](build-system.md#toolchain) § Toolchain lists. The ACPI tables
the [`shared/aml`](../shared/aml/README.md) host tests load are QEMU's, captured by `cargo xtask
capture-acpi`. Firmware tables captured from real hardware are not tracked; a defect found on one is
reduced to a hand-written test case.

---

## Harnesses

The tree is three layers, and each has one harness. A layer depends only on itself and the layers
below it; each harness tests its own layer, through the layers below it, on an image that holds its
layer and the layers below and nothing above.

| Layer | Harness | What the layer holds | The harness's image |
|---|---|---|---|
| Kernel | `ktest` | the bootloader, the kernel, the ABI crates, and ktest | the ESP alone: the bootloader, the kernel, and the ktest bundle (`/tests/ktest` in the `init` slot and the boot-time policy); the root and data partitions hold no file |
| Services | `svctest` | init, every core service, driver and filesystem driver, the runtime (`runtime/`), and the services' test features: svctest, its fixtures, the test-only drivers, and `ubench` | the kernel layer's, and the default service set (crashd included, except in the `crash-endpoint` set, which stages none), the test recipe of each service svctest configures for its checks, svctest, the fixtures of its set, and the test class files; no file of the programs layer: nothing under `/programs/` or `/tests/programs/`, and no recipe that names a file of the programs layer |
| Programs | `usertest` | the programs a user runs for their own purpose, their testers, and usertest | the whole system |

- **A component is in exactly one layer.** The record is
  [`xtask/src/layers.rs`](../xtask/src/layers.rs), and the CI selection reads it
  (§ Coverage tiers). Its source rows place every tracked file: a crate by its directory, a crate
  under `shared/` at the lowest layer of the crates that link it, and a recipe by the highest
  layer of the install paths it names. Its install rows place every file an image holds, by its
  install path: the layer it serves, and whether it is a test feature. A host test fails when a
  tracked file or an installed file is in no row, or when the two rows of a file disagree.
- **A dependency on a higher layer is forbidden**, in every form: a crate dependency, a path a
  component's code spawns, creates, opens or reads, a path a recipe names, a file a harness's
  staging puts in its image, and a crate feature. Cargo turns on, for a crate, every feature any
  package of one invocation asks of it, so `cargo xtask build` builds each layer's components in
  cargo invocations of their own, and no higher layer's manifest changes a lower layer's
  binaries. A process a phase needs is a fixture of the phase's own layer, never a component of a
  higher one. Host tests fail on a crate that depends on a crate of a higher layer, on a source
  below the programs layer whose code names an install path of the programs layer, on a bundle
  list that names a file above its harness's layer, and on a build invocation that builds the
  components of two layers.
- **A harness asserts on its own layer.** ktest on the kernel; svctest on the services, the runtime
  and the kernel objects they hand out; usertest on each program's real I/O surface, consuming the
  services as any program does. A tester asserts nothing about a service's internals.
- **A change in a layer can affect that layer's harness and those above it, never one below.** A
  component's checks live in its own layer's harness, so a change runs them wherever it can affect
  them.
- **A case** (`cargo xtask test`) belongs to the layer of the cell that runs it, and boots an image
  no higher than that layer's.
- **A test feature** (a harness, a tester, a fixture, a test-only driver, or a recipe, class file or
  data file only a test reads) installs under `/tests/` and reaches an image only through its
  harness's staging. A fixture that the component under test finds by its install path installs
  where that component looks, and is still a test feature: `test-dma`, which devmgr binds from
  `/services/drivers/`, and the test recipes, class files and data files under `/config/` and
  `/data/` that the services read from their own directories. Nothing but a program installs under
  `/programs/`.
- **The default image holds no test feature.** The pack composes four kinds of image from the
  record ([`xtask/src/disk.rs`](../xtask/src/disk.rs)): the kernel layer's for the ktest bundle,
  a services-layer image when svctest or ubench is staged, a test image, the whole system with its
  test features, when a staged recipe names a test feature (usertest's, a case's fixture's), and
  the default image, the whole system without any test feature, otherwise. Every pack reads its
  images back and fails when they hold a file their kind does not
  ([xtask/README.md](../xtask/README.md#the-image-check) § The image check).
- The layers have directories: `core/` is the kernel layer, `services/` the services layer, and
  `programs/` the programs layer; `abi/` is the kernel layer, `runtime/` the services layer,
  and `shared/` as the first rule says.

Each harness is launched as follows:

| Harness | Crate | Launch mechanism |
|---|---|---|
| `ktest` | [`core/ktest/`](../core/ktest/README.md) | Bootloader-loaded init replacement (`cargo xtask mkdisk --harness ktest`) |
| `svctest` | [`services/svctest/`](../services/svctest/README.md) | `svcmgr` spawns from `/config/svcmgr/services/` recipe (`cargo xtask mkdisk --svctest <set>`) |
| `usertest` | [`programs/usertest/`](../programs/usertest/README.md) | `svcmgr` spawns from `/config/svcmgr/services/` recipe; drives binaries under `programs/` through their real I/O surfaces. The terminal interactive test (the `terminal` case, `cargo xtask test terminal`) runs as a separate boot in the `usertest` CI cell; it drives the autostarted terminal through both input sources — keys over QMP through the live virtio-input driver, then the same sequence over the guest serial RX — and then keys again after a restart of the virtio-input driver |

`ktest` and `svctest` are authoritative for their own surface; the harness
itself owns its phases. `usertest` is an orchestrator that runs the per-program
tester binaries under `/tests/programs/` that its recipe names.

[`ubench`](../services/ubench/README.md), the userspace benchmark suite, is launched as
`svctest` is, from a recipe staged into `/config/svcmgr/services/`, and measures rather than
tests: it logs result lines, and passes when every benchmark ran
([Benchmarks](#benchmarks-bench-cell)).

---

## Reporting marker

Every harness MUST emit exactly one of these lines to the boot log on
completion:

```
[<harness>] ALL TESTS PASSED
[<harness>] SOME TESTS FAILED
```

`<harness>` is the harness name (`ktest`, `svctest`, `usertest`, `ubench`).

- For harnesses launched as a userspace service, `std::os::seraph::log!`
  with a name registered via `std::os::seraph::log::register_name(b"<name>")`
  produces the `[<name>]` prefix automatically; the harness payload is just
  `"ALL TESTS PASSED"` or `"SOME TESTS FAILED"`.
- For harnesses launched as the init replacement (`ktest`), logd is not
  available; the harness writes the full bracketed line directly to the
  serial port.

`cargo xtask run --runs`, which every CI boot uses, passes a run on the pass marker of the harness
the image boots, with that harness's name, never on the bare substring `ALL TESTS PASSED`, so a
line of another process holding it is not a pass. A harness launched as a service that dies before
its marker, as a fault in its own process does, fails the run: svcmgr logs
`service died: <harness>`, and `run` reads that line, before the harness's pass marker, as a
failure within its fail grace window. ktest has no supervisor to log its death: a fault of its own
thread logs no marker, and its boot stays a HANG at its budget
([xtask/README.md](../xtask/README.md#cargo-xtask-run) gives the verdicts). Per-tier
breakdown and counter lines (`PASS <name>`, `passed=`, `failed=`) are
harness-specific and MUST NOT include the bracketed summary substring.

---

## Per-program tester protocol

A program under `programs/<name>/` MAY ship a tester. Its author opts in or skips; absence is the
default. A test fixture under `services/fixtures/` ships none: svctest's phases drive the fixtures.

### Layout

- The tester crate lives at `programs/<name>/tester/`.
- The tester crate is a workspace member listed in the root `Cargo.toml`.
- The tester uses the standard userspace build profile (same as the
  program or fixture itself).

### Install

- The tester binary lands at `/tests/programs/<name>` in the sysroot,
  regardless of the tester crate's `[[bin]]` name.
- The install path is controlled by `xtask`'s `SPECS` entry for the tester
  crate; the tester crate MUST NOT rely on its own binary name to land at
  the correct sysroot path.
- The tester MUST be named in the `TESTERS` env entry of usertest's recipe
  (`rootfs/config/svcmgr/tests/usertest.svc`), the testers the image holds.
  usertest fails the run for each tester named and absent from
  `/tests/programs/`, for each one there that the list does not name, and
  for an empty list
  ([programs/usertest/README.md](../programs/usertest/README.md) § Testers).

### Contract

- The tester binary MUST exit `0` on pass and non-zero on fail.
- The tester MUST exit, and its stdout and stderr MUST close, within the
  bound usertest's recipe sets in `TESTER_BOUND_MS`. usertest kills a tester
  still running at the bound, reports it as FAIL, and runs the testers after
  it ([programs/usertest/README.md](../programs/usertest/README.md)
  § Testers).
- The tester binary's exit code is the authoritative verdict. Seraph propagates
  it natively, without POSIX 8-bit truncation (see
  [syscalls.md § `SYS_ASPACE_EXIT`](../core/kernel/docs/syscalls.md#sys_aspace_exit-54));
  the orchestrator reads it through `ExitStatus::success()`/`code()`.
- The tester SHOULD emit a final stdout line `[<name>-tester] PASS` or
  `[<name>-tester] FAIL` for log readability. The orchestrator does not
  rely on this line for the verdict.
- The tester drives the program under test, `/programs/<name>`, through its
  real I/O surface — stdio (via `std::process::Command` with
  `Stdio::piped()`), argv, environment, filesystem — and asserts whatever
  invariant fits that program.

### Seeds

- A tester that needs an authority no lookup gives (a seed-only name, or a
  cap with `GRANT`) takes it as a seed of usertest's recipe
  (`rootfs/config/svcmgr/tests/usertest.svc`): the recipe's `seed` line names
  it, and its env entry `TESTER_SEEDS` declares the slot for the tester
  (`<tester>:<slot>[,<slot>...]`, entries joined by `;`; slot 0 is usertest's
  own `pwrmgr.shutdown`).
- usertest hands the tester a copy of each declared seed as its bootstrap
  caps, in the order its entry names them, and the tester takes them with
  `ipc::bootstrap::request_slots` on its `creator_endpoint` before it writes
  to its stdout or stderr
  ([programs/usertest/README.md](../programs/usertest/README.md) § Seeds).
- A tester with no entry is spawned with no creator endpoint.

---

## Sysroot layout

```
sysroot/
├── services/                 # long-running userspace services
│   ├── …
│   ├── drivers/              # device drivers (virtio-blk, virtio-input,
│   │                         # virtio-console, virtio-rng, serial, framebuffer,
│   │                         # cmos-rtc | goldfish-rtc, iommu-vtd |
│   │                         # iommu-riscv, and the test-only test-dma)
│   └── fs/                   # filesystem drivers (fatfs)
├── programs/                 # program binaries
│   ├── hello
│   ├── shell
│   └── …
└── tests/                    # test harnesses, per-program testers, and
    │                         # test fixtures
    ├── ktest                 # kernel-surface harness (bootloader-loaded)
    ├── svctest               # services-surface harness
    ├── usertest              # programs-surface orchestrator
    ├── ubench                # userspace benchmark suite
    ├── drivers/              # test-only drivers bound only on demand
    │   └── test-fault        # fault-injection driver, bound by BIND_DRIVERS
    ├── fixtures/             # fixtures started as services
    │   ├── service-modes     # the service-role modes: crasher, memhog, stopsrc
    │   ├── debug-echo        # debug-port fixture (`debug-port` case)
    │   ├── hotplug-check     # PCI Express hotplug fixture (`hotplug` case)
    │   ├── …
    │   └── programs/         # fixtures spawned as programs
    │       ├── crashme
    │       ├── leader
    │       ├── program-modes
    │       ├── spawn-target
    │       ├── stdiotest
    │       └── …
    └── programs/
        ├── hello             # per-program tester for /programs/hello
        ├── shell             # per-program tester for /programs/shell
        └── …
```

`/services/` and `/programs/` MUST NOT contain test harnesses, per-program testers or test
fixtures; those live under `/tests/`. Test features also install under `/services/drivers/`,
`/config/svcmgr/tests/`, `/config/devmgr/tests/`, `/config/bundle/` (the ktest bundle's list) and
`/data/`, where the components under test look for them; the default image holds none of them, nor
anything under `/tests/` ([Harnesses](#harnesses)), and the install rows of
[`xtask/src/layers.rs`](../xtask/src/layers.rs) name each.
Under `/services/drivers/` is [`test-dma`](../services/drivers/test-dma/README.md), the test-only
driver of the `edu` DMA test device. Under `/tests/drivers/` is
[`test-fault`](../services/drivers/test-fault/README.md), a test-only fault-injection driver that
no drivers-directory pass at boot reads: devmgr binds it only through `BIND_DRIVERS`. Under
`/tests/fixtures/` are the test fixtures the harnesses spawn, sourced from
[`services/fixtures/`](../services/fixtures/README.md): under `/tests/fixtures/programs/` the ones
spawned as programs, `crashme`, `debugger`, `fsbench`, `leader`, `program-modes`, `spawn-target`,
and `stdiotest`, each an image of the program role, which the `programs` component keeps in the
program signing role, and none of which installs under `/programs/`; directly under
`/tests/fixtures/` the ones a harness recipe starts as services, `debug-echo`, `hotplug-check`, and
`service-modes`. `program-modes` is one image whose first argument names the mode, `capexhaust`,
`deadline`, `demandpaged`, `narrow`, `pipefault`, `pipestress`, `relrofault`, `stackoverflow`,
`threadchurn` or `threadstack`; `service-modes` likewise, `crasher`, `memhog` or `stopsrc`. Which
consumer spawns or drives each one is owned by
[services/svctest/README.md § Fixtures](../services/svctest/README.md#fixtures) for `svctest` phases
and by each fixture's README (`services/fixtures/<name>/README.md`, the modes of `program-modes` and
`service-modes` each a section of theirs). Under `/config/svcmgr/tests/` are the harness recipes,
and under `/config/devmgr/tests/` the test device class files the svctest recipe stages (see
[Gating](#gating)). Under `/data/` are `/data/test.txt`, a fixture shared by `svctest` and the
`shell` tester, and the build-synthesised `svctest`-only fixtures `/data/svctest/large.bin`,
`/data/svctest/bench.bin`, and `/data/svctest/signed/verified.dat`, the data-role fixture of
procmgr's verified read, which every pack signs ([signing.md](signing.md) § Signing).

---

## Gating

The default boot is interactive: no harness runs. It brings up the system
services and the `terminal` program, which autostarts from
`/config/svcmgr/services/terminal.svc` and is the keyboard consumer (see
[programs/terminal/README.md](../programs/terminal/README.md)).

`svcmgr` reads the recipes `/config/svcmgr/services/`'s signed index names and launches each
(see [services/svcmgr/README.md](../services/svcmgr/README.md)).
Test-harness recipes are not shipped there by default. Instead they live
in a sibling directory that `svcmgr` does not read:

```
rootfs/config/svcmgr/
├── services/                 # always loaded by svcmgr
│   ├── procmgr.svc
│   └── …
├── tests/                    # NOT loaded by svcmgr
│   ├── svctest.svc
│   ├── usertest.svc
│   ├── ubench.svc            # userspace benchmark suite; staged by the `bench` cell
│   ├── sessiond.svc          # sessiond with a fixture leader; staged with svctest and ubench
│   ├── crasher.svc           # restart-path fixture; co-staged with svctest
│   ├── crasher-worker.svc    # worker-fault restart fixture; co-staged with svctest
│   ├── crasher-boot.svc      # death-before-bootstrap fixture; co-staged with svctest
│   ├── crasher-once.svc      # one-shot death fixture; co-staged with svctest
│   ├── memhog.svc            # out-of-memory policy fixture; co-staged with svctest
│   ├── reserve-creator.svc   # reserve-creator fixture; co-staged with svctest
│   ├── stopsrc.svc           # stop-source fixture; co-staged with svctest
│   ├── crashd.svc            # crashd naming crashme; co-staged with svctest
│   ├── oomd.svc              # oomd with a 1000 ms cooldown; co-staged with svctest
│   ├── debug-echo.svc        # debug-port fixture; staged by `debug-port` case
│   ├── hotplug-check.svc     # hotplug fixture; staged by `hotplug` case
│   ├── hotplug-check-disk.svc # hotplug fixture's disk mode; staged by `hotplug` case
│   ├── reboot.svc            # reboot fixture; staged by `shutdown` case
│   └── gdb-target.svc        # GDB stub's target; staged by `debug-port` case
└── debug/                    # NOT loaded by svcmgr
    └── gdbstub.svc           # GDB stub template; staged, naming its target,
                              # by run --debug-target, and
                              # by `debug-port` case

rootfs/config/devmgr/
├── classes/                  # device class files, scanned
└── tests/                    # NOT scanned
    ├── test-dma.class
    ├── test-fault.class
    ├── serial-deny.class
    ├── input-deny.class
    ├── hwrng-deny.class
    └── framebuffer-deny.class
```

To enable a harness for a boot, copy its recipe from
`sysroot/config/svcmgr/tests/` into `sysroot/config/svcmgr/services/` after
`cargo xtask build`, then repack with `cargo xtask mkdisk --repack-only` before
`cargo xtask run` (`run` boots the existing `disk.img`, and a normal `mkdisk`
re-mirror prunes the hand-staged recipe). A staged recipe that names a test feature, usertest's
among them, makes the pack write a test image, the whole system with its test features; a sysroot
that stages none packs the default image, which holds no test feature
([Harnesses](#harnesses)). svctest and ubench are staged by `mkdisk` itself: svctest
with a fixture set (`--svctest ci|burn-in|none|crash-endpoint`, below), ubench with `--ubench`:

```sh
cargo xtask build
cargo xtask mkdisk --repack-only --svctest none
cargo xtask run --test-devices
```

`mkdisk --svctest` and `mkdisk --ubench` (the two conflict) stage a services-layer image: they
remove from `/config/svcmgr/services/` every recipe that names a file of the programs layer (the
autostarted `terminal` and the default sessiond among them) and stage sessiond's test recipe
(`tests/sessiond.svc`), whose session leader is the fixture `/tests/fixtures/programs/leader`, over
the default one. The pack then writes a services-layer image, which holds no file of the programs
layer (`/programs/`, `/tests/programs/`, `/tests/usertest`, and every recipe that names one,
`/config/svcmgr/tests/usertest.svc` among them), whenever the staged services hold `svctest.svc` or
`ubench.svc`, so a later `--repack-only` keeps the omission and the boot runs no program.

`mkdisk --svctest` also stages the test class files of `sysroot/config/devmgr/tests/` into
`sysroot/config/devmgr/classes/`, the directory svcmgr reads class files from, and the svctest
boot runs with `--test-devices`, which attaches `edu` and five QEMU `pci-testdev` functions that
no other launch attaches and no production driver binds. svctest fails, naming the flag, when they
are missing.

**svctest fixture sets.** A fixture is a test recipe that svctest's phases drive when it is staged
beside svctest (`services/svctest/fixtures`). `cargo xtask mkdisk --svctest <set>` stages svctest's
recipe with the fixtures of one named set, removes every other fixture's recipe from
`/config/svcmgr/services/`, and writes the set into the staged recipe's `env` line as
`SVCTEST_FIXTURES=<fixture>,...` (`none` for the empty set) before the pack signs it:

| Set | Fixtures | Used by |
|---|---|---|
| `ci` | `crasher`, `crasher-worker`, `crasher-boot`, `crasher-once`, `memhog`, `reserve-creator`, `stopsrc` | the canonical svctest cells, and the local host runs that stage svctest as they do |
| `burn-in` | `memhog`, `reserve-creator`, `stopsrc` | the burn-in svctest cell |
| `none` | none | a boot of svctest alone |
| `crash-endpoint` | none | the crash-endpoint boot: no crashd, and svctest runs only its startup phases, `svctest_fixtures` and `crash_endpoint` |

svctest's `svctest_fixtures` phase, right after its startup phases, fails the run unless the image
stages exactly the fixtures the record declares, naming each recipe that disagrees: a declared
fixture whose recipe is missing, or a fixture recipe the record does not declare. It fails the same
way without the record, so a hand-copied svctest recipe does not boot, and when the recipes of
oomd or sessiond, the default services its phases drive, are missing. A phase whose fixture the
set does not declare skips, or skips the part the fixture drives, and logs
`phase=<phase> skipped: <recipe> not staged`.

Every set stages oomd's test recipe, `tests/oomd.svc`, over the default one: the same service with
`OOMD_COOLDOWN_MS=1000` in place of the default's 5000, the grace (2000 ms) and `OOMD_STOP=yes`
unchanged. The `ci`, `burn-in` and `none` sets stage crashd's test recipe, `tests/crashd.svc`, over
the default one: the same service with `CORE_DUMP=crashme`, so crashd writes a core of each
`crashme` death, and `CRASHD_OOM_STALL_MS=5000`, which svctest's `crashd_oom_hold` phase reads as
the least time a fault memmgr declined for want of memory is held before the hold times out, still
longer than oomd's grace and cooldown together (3000 ms); svctest's `crashd_*` phases check them
([Crash reports](#crash-reports)), and its `crashd.core` seed is the authority for the live cores.
The `crash-endpoint` set stages no crashd, so procmgr's crash endpoint is free for svctest's
`crash_endpoint` phase; the set records `SVCTEST_PHASES=crash_endpoint` in svctest's recipe, and
`svctest_fixtures` fails an image with crashd staged when that record is set, and one without
crashd when it is not.

The usertest boot stages no crashd test recipe and runs no faulting fixture. Its testers, `hello`
and `shell`, are the two under `/tests/programs/`; it is staged by hand and booted with
`--crash-reports none`:

```sh
cargo xtask build
cp sysroot/config/svcmgr/tests/usertest.svc sysroot/config/svcmgr/services/
rm -f sysroot/config/svcmgr/services/terminal.svc
cargo xtask mkdisk --repack-only
cargo xtask run --crash-reports none
```

`ktest` is gated separately: it lives in the bootloader-loaded bundle,
not in `svcmgr`'s recipe set. To run `ktest`, swap which binary backs
the bundle's `init` entry:

```sh
cargo xtask build
cargo xtask mkdisk --harness ktest
cargo xtask run
```

Reset to the default-init bundle by re-running `cargo xtask build` or
`mkdisk --harness init`. ktest's runtime options bake in as
compile-time defaults in `core/ktest/src/cmdline.rs::KtestConfig::DEFAULT`, or
`KtestConfig::BENCH` in a `cargo xtask build --ktest-bench-only` build
(see [xtask/README.md](../xtask/README.md#cargo-xtask-mkdisk)).

CI's ktest boots, the `ktest` cells' own boot and the burn-in's ktest boots, run at the fixed 4
CPUs on the fixed device set ([Coverage tiers](#coverage-tiers)), where no test's skip condition
holds: every CPU minimum in ktest is 4 or less, and the launch hands ktest every device and
capability a test gates on. Each carries `--fail-also ' SKIP '`, so a test that logs its SKIP line
([core/ktest/README.md](../core/ktest/README.md)) fails the boot, as does a test whose CPU minimum
is above 4. The `bench` cell's boots carry no such check: its one-CPU boots skip what needs more
CPUs, a functional ktest boot runs every benchmark at 4 CPUs, and `bench-check` judges the cell's
counts ([Benchmarks](#benchmarks-bench-cell)). A local boot at fewer CPUs keeps its skips.

### Interactive input (`terminal` case)

Interactive input cannot be exercised by an autonomous recipe: keysyms must come
from real `EV_KEY` events on the virtio-input device, and serial bytes from a
real UART receive, neither of which the guest can synthesise for itself. Input
is also not tested by a second device reader — the `terminal` program is the
system's input consumer (it autostarts from
`/config/svcmgr/services/terminal.svc`), and each device delivers a given event
to one reader. So input is tested *through* the terminal.

`cargo xtask test terminal` boots QEMU with a QMP control socket, waits for the
terminal's `terminal: READY for injection` marker, then drives both input
sources and a restart of the input driver in one boot (command reference:
[xtask/README.md § The `terminal` case](../xtask/README.md#the-terminal-case)):

1. **Keyboard round** — inject a known key sequence via QMP `input-send-event`
   (through the live `virtio-keyboard-pci`), assert the terminal's local echo
   and the relayed child output appear on the serial stream.
2. **Serial RX round** — on a cleared transcript, write the same sequence to the
   guest UART receive path via QEMU's bidirectional `-serial stdio` (host stdin
   reaches the guest serial RX), assert the same echo + child round-trip.
3. **Input restart round** — the host kills the virtio-input driver through the
   GDB stub, which the test stages on that driver and attaches over the debug
   port; devmgr restarts it at the class's next ordinal
   ([Driver Restart](../services/devmgr/docs/responsibilities.md#driver-restart)).
   The terminal must log that it holds the instance at ordinal
   1, and, on a cleared transcript, the keyboard sequence injected again must give
   the same echo and child output, which a terminal still holding the dead
   driver never shows.

Unlike the other harnesses the verdict is computed by the host (the terminal
cannot know the expected sequence), and the host kills QEMU on success. The
driver carries no test hooks — injection happens at the hardware boundary, so
the whole stack (device → decode/IRQ → IPC → terminal → child → output) is
exercised as in production. All three rounds run on both arches.

The terminal autostarts on a normal boot, and the test stages the GDB stub itself
and removes it again, so no recipe staging is needed; just build, repack, and run
the host driver (not `run --runs`, which cannot inject):

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test terminal
```

This is the reusable foundation for interactive tests of the terminal, the
shell (#112), and future consumers — they reuse the runner by swapping the
terminal's session leader and the expected strings. It subsumes the keysym-decode
coverage of the former standalone input smoke test: the echoed `help` proves
lowercase keysym decode, and Return/Backspace prove the named-key decodes. In
CI the `usertest` cell runs it as a case of `cargo xtask test --cell usertest`, after the cell's own
boot, rather than as a separate matrix dimension that would multiply with each arch.

### Snapshot resume (`vmgenid` case)

Whole-VM-snapshot reseed (#395) cannot be exercised by an in-guest recipe: the
generation change only happens when the hypervisor restores saved state, and
QEMU deliberately exposes no QMP/HMP way to change the GUID at runtime.
`cargo xtask test vmgenid` (x86_64 only — QEMU's riscv64 `virt` machine has no
VMGENID) drives QEMU's save/restore recipe host-side:

1. Boot with a fixed generation GUID; wait for the kernel's
   `entropy: vmgenid armed` marker (bootloader VGIA discovery + kernel
   consumer wired) and the terminal's READY marker.
2. Save the guest via QMP `migrate` to a state file; `quit` the source
   (releasing the raw disk image's write lock).
3. Boot again with a different GUID and `-incoming exec:cat <state>`; assert
   the kernel's `entropy: VM generation change detected` marker — printed by the
   BSP timer tick's poll of the same live GUID (the per-draw reseed compare is
   separate; see [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
4. Inject the terminal `help` sequence over QMP and assert the shell's output:
   the resumed guest still draws randomness and schedules normally after the
   forced reseed.

See [xtask/README.md § The `vmgenid` case](../xtask/README.md#the-vmgenid-case)
for the command and [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)
for the snapshot-detection design.

Same boot requirements as the `terminal` case (default boot set, terminal
autostarted); the host computes the verdict and kills QEMU. In CI the x86_64 `usertest` cell's
`cargo xtask test --cell usertest` runs it.

### KASLR randomization (`kaslr` case)

KASLR (#252) cannot be verified from inside the guest: it must observe that the
layout *differs* across separate boots. `cargo xtask test kaslr [--arch]` (both
arches) drives this host-side against the ktest bundle:

1. Boot twice with KASLR enabled; scrape the kernel's serial-only
   `kaslr: slide=… image_base=… dm_base=…` line (emitted in Phase 1) and assert
   the joint `(slide, dm_base)` differs between the two boots. A single-dimension
   collision is ~1/1000, so the compare is joint and retries boot B once — a
   false failure is ~1e-8.
2. Stage the `\EFI\seraph\nokaslr` override knob, repack the disk images in the
   layout they have, boot once, and assert the deterministic layout (slide 0,
   image at its link base, direct map at the mode floor); the KASLR-enabled
   images are always restored in that layout afterward.

See [xtask/README.md § The `kaslr` case](../xtask/README.md#the-kaslr-case) for
the command and [memory-model.md](memory-model.md) for the randomized layout.

Requires a populated sysroot with the ktest bundle composed
(`cargo xtask mkdisk --harness ktest`). The `kaslr:` line is emitted only
through the kernel's serial-only console class (see
[cross-boundary-disclosure.md § Kernel console diagnostics](../core/kernel/docs/cross-boundary-disclosure.md#kernel-console-diagnostics)).
In CI the `ktest` cell's `cargo xtask test --cell ktest` runs it (both arches, both profiles),
after the cell's own boot and a plain `cargo xtask mkdisk`, which drops the `mapredo` knob of the
cell's staging.

### Steps 6 and 7 redo (ktest cell)

The bootloader redoes its steps 6 and 7 (frees every allocation of both and
runs them again with twice the slack) only when the final memory map's buffer
outgrows the entry array step 6 sized, which QEMU's firmware never makes it do (see
[memory-map.md § Sizing the Entry Array](../core/boot/docs/memory-map.md#sizing-the-entry-array)).
CI's `ktest` cell stages the `\EFI\seraph\mapredo` test knob
(`cargo xtask mkdisk --harness ktest --knob mapredo`), which makes the first attempt redo whatever
its map's size, and its own boot, on the ktest bundle and under the cell's boot budget, requires the
bootloader's `mapredo knob present; redoing steps 6 and 7` line. The boot host test
`the_mapredo_knob_redoes_the_first_attempt_alone` (`core/boot`) holds the redo to one. Locally:

```sh
cargo xtask build --arch <arch>
cargo xtask mkdisk --arch <arch> --harness ktest --knob mapredo
cargo xtask run --arch <arch> --runs 1 --timeout <seconds> \
    --require 'mapredo knob present; redoing steps 6 and 7'
```

A plain `cargo xtask mkdisk` removes the knob.

### Benchmarks (`bench` cell)

Each kernel benchmark of ktest's Tier 3 ([core/ktest/README.md](../core/ktest/README.md)) logs one
result line, its samples' summary in the form
[shared/bench/README.md § Result line](../shared/bench/README.md#result-line) gives. A functional
ktest boot runs every benchmark 8 times, a smoke run whose lines no check compares; the bench-only
image (`cargo xtask build --ktest-bench-only`) runs Tier 3 alone, 4096 iterations each, for the
lines that are compared. The userspace paths are measured by the
[`ubench`](../services/ubench/README.md) suite, in a boot of the regular init image with its
recipe (`/config/svcmgr/tests/ubench.svc`) staged by `cargo xtask mkdisk --ubench`, which leaves
no program in the image; it logs its own
lines and fsbench's.

CI's `bench` cell, one per architecture, takes both in the release profile from its architecture's
release build job (`cargo xtask build --release --ktest-bench-only`) and boots them under QEMU's
icount (`cargo xtask run --icount`): one guest clock tick per retired instruction while a vCPU runs,
so the count of a window that does not idle is the same in every run of one build, whatever the
runner's load. While every vCPU idles, the guest's clock follows the host's time up to its next
timer deadline (QEMU's `sleep=on`), so a device completion ends the idle as it would on hardware,
and a window that idles counts host time. It boots each three times
at one CPU and once at four, the ubench boots with a framebuffer (`--display framebuffer`) and their
logs saved in `ubench/` beside the ktest boots', and one `cargo xtask bench-check --mode icount`
over both sets compares each measurement's lowest p50 over the runs that reported its suite with its
baseline under `xtask/baselines/bench/icount/`
([xtask/README.md § `cargo xtask bench-check`](../xtask/README.md#cargo-xtask-bench-check)).

The one-CPU counts gate: a count further from its baseline than the larger of 1% of it and 8
instructions, in either direction, fails the cell, as does a measurement whose measured loop idled
(below), a measurement with no baseline, a
baseline no run measured, and a benchmark's `FAIL` line. A run whose change owes no ktest cell
skips the ktest boots and does not check the ktest suite's baselines (`bench-check --skip-suite
ktest`), and a rewrite from that run leaves the ktest suite's files as they are. A count that fell
past its band fails too, since the stale baseline would let a later regression of the same size
through. A PR that
moves a count on purpose rewrites the baselines of the benchmarks it moved from its own CI run
(`cargo xtask bench-baseline --from-run <run id>`) and states the change and its reason in its
body. The four-CPU counts are reported, not gated: the interleaving of the CPUs moves them.

The cell measures the release profile because hardware runs it, and a count is worth what it
says about hardware. The debug profile adds debug assertions and overflow checks, and leaves out
of line the calls the release build's fat LTO inlines, in proportions that differ from path to
path, so a count moved in the debug profile does not predict the count moved in release. A
regression that exists only in the debug profile, such as a debug assertion added to a hot path,
is therefore not gated: it costs nothing on hardware, and the functional cells still boot both
profiles. [core/kernel/docs/hot-path-account.md](../core/kernel/docs/hot-path-account.md)
§ Profile gives the counts of both profiles per path.

A one-CPU count gates only when its timed window does not idle. While every vCPU idles, the
guest's clock follows the host's time, so a window that idles counts host time, which no band
bounds: one blocked on a device completion, which arrives at host time, counts the host's I/O
latency, and one waiting on a timer counts the host time its idle took. `fsbench.write`, which
writes through the filesystem's page cache to the disk, is such a benchmark at every size, and is
reported, not gated; a regression of the write path's instructions shows in the cell's report and
in host mode, not as a failure. `fsbench.read` gates: its untimed open, fixture check and warm-up
reads fill the filesystem's page cache with the file, so no timed read waits on the disk. A
benchmark is classified by the same test: one whose timed samples idle, on a device, a timer or
any other event, joins the set (`ICOUNT_IO_BOUND` in `xtask/src/benchmark.rs`). The cell checks
the test: each result line reports, as `idle_halts=`, the halts of its measuring CPU over the
measured loop
([shared/bench/README.md § Idle halts](../shared/bench/README.md#idle-halts)), and `bench-check`
fails a gating measurement whose line reports a halt or no count, naming the measurement and its
halts.

Icount counts instructions, not time: a change that costs cycles without instructions (a cache
miss, a TLB flush, a contended line) does not move them. Time is measured on the reference host
(`--mode host`, x86_64 under KVM, on the release build the cell measures, per-measurement bands
in `xtask/baselines/bench/host/x86_64/BANDS`), and is report-only: no host-mode baseline is
checked in yet, so no PR owes a host-mode run.

### Crash reports

The crash service, crashd, is in the default service set
(`rootfs/config/svcmgr/services/crashd.svc`) and logs a report block for each process that dies
on a fault ([services/crashd/README.md](../services/crashd/README.md)). No harness reads the
system log from inside the guest, so `cargo xtask run --runs N --crash-reports reports|none`
checks the blocks in each boot's serial log, with the parser of the format crashd emits
([services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md)): every block
must be complete and hold the fields its kind, thread, and status require.
- `--crash-reports reports` reads an svctest boot of a set that stages crashd, whose `crashd_faults`
  phase runs the `crashme` fixture
  ([services/fixtures/crashme/README.md](../services/fixtures/crashme/README.md)): the log must also
  hold one `vm` and one `exception` block of `crashme`'s main thread and one `exception` block of a
  `spawned` thread, whose fault the fixture takes while a sibling is held blocked on a fault at the
  same instruction, each tied to `crashme` through the badge logd's `reclaim:` line names, complete,
  its walk starting at its instruction pointer, matched by the kernel's `handler declined` line
  carrying the block's id, and carrying the stack pointer the kernel's register dump of that line's
  thread prints, so the block read the thread that faulted. The `vm` block's `addr`, the fault
  message's address, must also be the faulting address that dump prints (`cr2` on x86_64, `stval` on
  riscv64), so the dump names the access that faulted.
- `--crash-reports none` reads a boot in which no crash service reports: the usertest boot, which
  runs no faulting fixture, and the `crash-endpoint` svctest boot, which stages no crashd. The log
  must hold no block, the check that the absent service changes nothing a fault does.

The svctest boot's crashd names `crashme` in its `CORE_DUMP` ([Gating](#gating)), so each of the
fixture's faulting deaths also leaves an ELF core in `/crash`, which svctest's `crashd_cores` phase
checks in the guest: its machine, the faulting thread's signal, instruction pointer and stack
pointer against the page runs it holds, the illegal instruction's bytes, and the `worker` core's
threads ([services/fixtures/crashme/README.md](../services/fixtures/crashme/README.md)). Its
`crashd_live_core` phase asks crashd, through the `crashd.core` seed, for a live core of the
running fixture and checks that the fixture ran on unchanged and that the core records its threads,
their stacks and a page it marked, and none of the binary's text; asks for one of a fixture on the
core path, on an account that cannot fund a snapshot, and checks the refusal asked for none; and
asks for one that procmgr refuses after it took frames and one that crashd refuses after the
capture, for a declaration made during the request, and checks that each left svctest's charge as
it was ([crashd Operation § Live Core](../services/crashd/docs/operation.md#live-core)). The phase
also checks that a spawn returns with its death bridge's pages charged. A core is checked in the
boot, not in the log; `gdb` reading one is checked by hand
([services/crashd/docs/core-format.md](../services/crashd/docs/core-format.md) § Reading a Core).

The svctest boot's crashd also holds a page fault memmgr declined for want of memory, for up to
5000 ms ([crashd Operation § Hold](../services/crashd/docs/operation.md#hold)). The
`crashd_oom_hold` phase, which runs after `swap_commit`, fills memory down to memmgr's growth floor
and has the fixture write a page it has not touched, reading the stall from the staged crashd
recipe: once the filler gives the memory back within the stall, and the write completes after the
hold; once the filler keeps it until the fixture has died, and the fixture dies of the fault at
least the stall after its write, with no core written.

In CI the svctest cell's `ci` boot passes `--crash-reports reports` to `cargo xtask run --runs 1`,
its `crash-endpoint` boot and the usertest cell's boot pass `--crash-reports none`. Each makes the
first or the second check on its boot's own log
([xtask/README.md](../xtask/README.md#classified-boots---runs)).

The crash service cannot cover every process. init, memmgr, and procmgr are not created by procmgr,
and the debug port's virtio-console driver and crashd declare themselves undebuggable, as svctest
and the GDB stub, debug-authority holders, do in a boot that stages them; their faults leave only
the kernel's `fault unhandled` and `USERSPACE FAULT` lines. A thread that never registered with
procmgr is reported without registers or a stack walk ([crashd Operation §
Limits](../services/crashd/docs/operation.md#limits)).

### Log levels (usertest cell)

The log level of each service init spawns comes from the boot bundle's log-level configuration,
and a driver devmgr spawns and a fatfs instance vfsd spawns inherit their spawner's
([services/init/docs/bootstrap.md](../services/init/docs/bootstrap.md) § Log levels). The
committed configuration sets no level, so no default boot shows whether a level reaches its
service. CI's `usertest` cell packs a configuration setting vfsd to debug
(`services/init/log-levels-vfsd-debug.conf`, `vfsd = debug`) with its staging, and its own boot
requires vfsd's and fatfs's debug lines and fails on devmgr's or procmgr's. Locally, after the
usertest staging of [Gating](#gating):

```sh
cargo xtask mkdisk --arch <arch> --repack-only \
    --log-levels services/init/log-levels-vfsd-debug.conf
cargo xtask run --arch <arch> --runs 1 --require '\[vfsd\] DEBUG ' \
    --require '\[fatfs\] DEBUG ' --fail-also '\[(devmgr|procmgr)\] DEBUG '
```

### Reboot (`shutdown` case)

A reboot ends the boot that makes it, so no in-guest harness can check it, and every harness boot
ends in a power-off instead. `cargo xtask test shutdown --cause reboot [--arch]` (both arches), the
`shutdown` case's reboot boot, checks it host-side:

1. Stage the `reboot` fixture's recipe (svctest's `reboot` role, seeded with
   `pwrmgr.shutdown`) from `/config/svcmgr/tests/` into `/config/svcmgr/services/`, and repack the
   disk images in the layout they have.
2. Boot the current sysroot once with a QMP socket. The fixture logs
   `reboot fixture: requesting REBOOT` and sends pwrmgr `REBOOT`. On x86_64 pwrmgr has acpid write
   the FADT's `RESET_VALUE` to its `RESET_REG` (acpid logs `RESET: RESET_REG`); on riscv64 it
   makes the SBI system reset call (cold reboot).
3. QEMU runs with `-no-reboot`, so the reset ends it. The test passes on the fixture's line, on
   x86_64 acpid's line, a QMP `SHUTDOWN` event whose reason is `guest-reset` (a power-off gives
   `guest-shutdown`), and QEMU's own exit.
4. Remove the recipe and repack the images in that layout again, whatever the outcome.

See [xtask/README.md § The `shutdown` case](../xtask/README.md#the-shutdown-case) for the command.
In CI it is the first boot of the `shutdown` case, which each `usertest` cell runs (both arches,
both profiles), on the default boot the cell's `cargo xtask mkdisk` restored.

### Power button (`shutdown` case)

A press of the power button comes from outside the guest, so no in-guest harness can make one.
`cargo xtask test shutdown --cause power-button` (x86_64 only: QEMU's riscv64 `virt` machine has a
hardware-reduced ACPI with no fixed power button) checks it host-side:

1. Boot the current sysroot once with a QMP socket, and wait for acpid's `events armed` line,
   which it logs once it has taken the SCI and enabled the fixed power-button event, and the
   terminal's READY line.
2. Send QMP `system_powerdown`, which on q35 sets `PWRBTN_STS` in the PM1 event block and
   raises the SCI. acpid's event thread finds the press and logs `power button pressed`; pwrmgr,
   waiting in acpid's `WAIT_EVENT`, logs `power button: shutting down` and powers off through
   acpid's `SLEEP(5)` (acpid logs `SLEEP(5): PM1a_CNT`).
3. The test passes on the three lines, a QMP `SHUTDOWN` event whose reason is `guest-shutdown`, and
   QEMU's own exit.

See [xtask/README.md § The `shutdown` case](../xtask/README.md#the-shutdown-case) for the
command and [services/acpid/README.md](../services/acpid/README.md) § Events for the event path.
Same boot requirements as the `terminal` case (default boot set, terminal autostarted). In CI it is
the `shutdown` case's second boot in the x86_64 `usertest` cells, after the reboot boot.

### Core death (`shutdown` case)

The death of a core service, or the permanent death of a critical one, powers the system off
([supervision.md § Core Set and System Death](supervision.md#core-set-and-system-death)). No
service carries a hook that could make it die, so `cargo xtask test shutdown --cause
<cause>[,<cause>...] [--arch]` (both arches; the causes memmgr, procmgr, procmgr-reaper, svcmgr,
devmgr, vfsd and logd) kills each one from outside the guest, one boot per cause, by moving one of
its threads to program counter 0, which no process maps; the thread's instruction fetch faults, and
the fault is terminal. Two routes reach the thread:

- **The GDB stub service**, for the services procmgr creates: svcmgr, devmgr, vfsd and logd. The
  command stages the stub naming the target, as `run --debug-target` stages it, and boots with the
  debug port. Once the stub logs its attach, the host connects over the port, moves the target's
  main thread and detaches, which gives the target its crash bindings back, and the thread runs
  into the fault. A main thread blocked in an IPC call takes the stub's stop only at the call's
  return, so the host reads its program counter again until the stub holds it. svcmgr is killed
  at the attach, while the boot waits on it. devmgr and vfsd are released at the attach and held
  again once the terminal's READY line and svcmgr's reconciliation line have appeared, as
  supervised services. logd is killed at the attach, as svcmgr is, which can fall before logd asks
  svcmgr for its bootstrap round, a death svcmgr routes as any other ([Restart Protocol § Death
  detection](../services/svcmgr/docs/restart-protocol.md#death-detection)). When init-logd's
  `handover complete; init-logd thread exiting` line has not appeared before the first kill,
  whether the first instance died before its bootstrap request or after it (before its release),
  the check requires it after the first restart, since no instance released init-logd and the
  restarted one must. logd restarts, so it
  is killed again after each `service restarted: logd` line, through the stub's attach to the new
  instance, four times in all: the fourth death finds svcmgr's restart budget (three per 60 s
  window) spent and is permanent. The stub's
  lines reach the serial line through logd once logd has taken the log over from init, so a stub
  holding logd cannot log its attach: for logd the host connects once svcmgr's
  `svcmgr: launching: logd` line has appeared, and the stub answers its first request once it
  holds logd.
- **QEMU's own gdbstub**, for memmgr and procmgr, which init creates with raw syscalls, so no
  debugger can attach to them. Once the terminal's READY line and pwrmgr's `core-death power-off
  armed` line have appeared, the host sets a hardware breakpoint on a function of the target's
  binary, at the image bias init logs for it plus the function's address in the binary's symbol
  table, read from the symbols store's file of its build
  id ([docs/build-system.md](build-system.md#symbols-store) § Symbols Store), and types `hello` at
  the shell over the serial line, whose spawn and reap run it: `memmgr::admit` (memmgr's receive
  loop, in an allocation's admission), `procmgr::handle_create` (a procmgr request worker, in the
  create), and `procmgr::process::reap_dead` (procmgr's reaper, a thread other than its main
  thread, in the reap). On each stop it checks that the program counter is the function's and the
  code there is the binary's, since another process can run code at the same address, moves that
  CPU's program counter, removes the breakpoint, and resumes the VM.

A boot passes when, after the kill, QMP's `SHUTDOWN` event gives reason `guest-shutdown` and QEMU
exits on its own within two minutes. The paths it covers are pwrmgr's core-death power-off for
memmgr, procmgr and svcmgr (the core-death queue, and the address-space observer for a procmgr
thread other than the main one; [supervision.md § Observing the Core
Set](supervision.md#observing-the-core-set)), and svcmgr's `critical service unrecoverable`
shutdown through the actuator for devmgr, vfsd and logd. See
[xtask/README.md § The `shutdown` case](../xtask/README.md#the-shutdown-case) for the command.
Same boot requirements as the `terminal` case (default boot set, terminal autostarted). In CI they
run as the `shutdown` case's boots after the reboot boot (after the power-button boot on x86_64)
inside each `usertest` cell (both arches, both profiles).

### Hardware-reduced power-off

On a hardware-reduced x86-64 platform, whose FADT sets `HW_REDUCED_ACPI` and has no `PM1a_CNT`,
acpid's `SLEEP(5)` and pwrmgr's core-death power-off write the FADT's `SLEEP_CONTROL_REG`
([acpid § Power requests](../services/acpid/README.md#power-requests);
[supervision.md § Core Set and System Death](supervision.md#core-set-and-system-death)). No QEMU
machine boots the system on such a platform. QEMU's one hardware-reduced x86-64 machine,
`microvm` with `acpi=on`, decodes no port 0x61, so the 8254 gate the kernel measures its clock
through, where CPUID leaf 0x15 gives no TSC rate, reads all-ones and the 8254 gives no rate; it
publishes no MCFG, so devmgr finds no ECAM window; and the boot loader's `Mmio` apertures do not
cover the ECAM window its DSDT names. So the platform is tested by this procedure, on a machine
that meets the system's requirements, a TSC rate source among them (CPUID leaf 0x15, or else the
8254 PIT; [platform-requirements.md § Required](platform-requirements.md#required)), and
publishes an MCFG ([services/devmgr/docs/pci-enumeration.md § ECAM Configuration
Space](../services/devmgr/docs/pci-enumeration.md#ecam-configuration-space)):

1. Build the x86-64 sysroot, stage the svctest recipe as § Gating describes (the test class files
   too), repack `disk.img`, write it to a boot device of the machine, and read the log on its
   serial line.
2. Boot it. The log shows acpid's `SLEEP_CONTROL_REG: port ...` or `SLEEP_CONTROL_REG: memory ...`
   line, its `QUERY_SLEEP(5): SLEEP_CONTROL_REG ...` line, and pwrmgr's
   `core-death power-off armed`.
3. svctest ends with `ALL TESTS PASSED` or, without the QEMU test devices, which no machine has,
   `SOME TESTS FAILED`; either way it sends `SHUTDOWN`. The log shows acpid's
   `SLEEP(5): SLEEP_CONTROL_REG ...` line, and the machine powers off.

The procedure passes when all three hold. The core-death write itself, pwrmgr's store to
`SLEEP_CONTROL_REG`, is not run: no route kills a core member on real hardware, since no core
service carries a hook that could make it die (§ Core death), and the `shutdown` case's death boots
run on q35. Host tests cover what the write depends on: devmgr's sleep registers read from a
hardware-reduced FADT (`services/devmgr/firmware`), the value written
(`ipc::acpid_labels::sleep_control_value`), acpid's writes (`acpid::power`) and pwrmgr's reading of
the `QUERY_SLEEP` answer (`pwrmgr::power_off`).

### Debug port (`debug-port` case)

The debug port, the byte transport a debugger stub speaks to a host debugger over, is a
`virtio-console` device that a launch attaches only with `--debug-port`, and whose host end QEMU
serves as a TCP port
([services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md)).
No guest-side check can show that bytes cross it, since its far end is the host.
`cargo xtask test debug-port [--arch] [--port]` (both arches) checks the transport host-side in
the case's first boot:

1. Stage the [`debug-echo`](../services/fixtures/debug-echo/README.md) fixture's recipe from
   `/config/svcmgr/tests/` into `/config/svcmgr/services/`, and repack the disk images in the
   layout they have.
2. Boot the current sysroot once with the debug port, and wait for the fixture's
   `READY on the debug port` line on the serial stream.
3. Connect to the port and drive one GDB remote serial protocol exchange, framed at both ends by
   `shared/gdb-rsp`: `qSupported` and `?` in acknowledged mode, a packet with a bad checksum, which
   must be refused with `-`, the interrupt byte, `QStartNoAckMode`, then in no-ack mode a binary
   echo of every byte value through the escapes and a packet past the fixture's buffer, which must
   be refused with `E02`.
4. On the same connection, restart the port's driver under the fixture: kill the
   `virtio-console` driver through QEMU's gdbstub, which the boot attaches, at a hardware
   breakpoint in the function it runs on each of the fixture's reads, its bias taken from
   procmgr's `spawn image bias=0x… (/services/drivers/virtio-console)` line (the driver declares
   itself undebuggable, so no guest debugger reaches it); wait for the fixture's
   `debug port driver at ordinal 1` line once devmgr has restarted the driver at the class's next
   ordinal ([services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md)
   § Driver Restart); then echo through the restarted driver.
5. Kill QEMU, remove the recipe, and repack the images in that layout again, whatever the
   outcome.

The host computes the verdict and kills QEMU, as for the `terminal` case; the fixture invokes no
shutdown. See [xtask/README.md § The `debug-port` case](../xtask/README.md#the-debug-port-case)
for the command. No canonical CI cell attaches the debug port, so the boot is the `debug-port`
device cell of the local and release host runs (Coverage tiers below).

### Signature refusals (`signing` case)

Every verifier of [signing.md](signing.md) § Which Stage Verifies What refuses an object that
does not verify, and a refusal path no boot takes is not shown to work. `cargo xtask test signing
[--arch] [--release]` (both arches) boots the current sysroot eight times from disk images that
carry objects no build makes, written in place of the sysroot's files at pack time, so the
sysroot itself is never changed:

1. `kernel`: the kernel with a body byte flipped. The bootloader refuses it,
   `Failed(BodyHash)`.
2. `bundle`: the bundle's `/services/drivers/virtio-blk` entry with a body byte flipped. The
   bootloader refuses it, `Failed(BodyHash)`.
3. `policy-missing`: the bundle without its boot-time policy entry, `/config/boot/policy.conf`.
   The bootloader refuses the bundle, naming the entry it lacks.
4. `revoked`: a bootloader built under the build's trust store with the signing key revoked. It
   refuses the kernel, `Failed(Revoked)`.
5. `rootfs`: `/services/timed` with a body byte flipped, `/services/pwrmgr` signed with the data
   role alone, and `/services/crashd` signed by a key no anchor holds. procmgr refuses each
   (`Failed(BodyHash)`, `Failed(Role)`, `Untrusted`) and svcmgr reports each refused launch.
   The kernel and `/programs/terminal` each carry a record of that key before their own, which
   the bootloader and procmgr skip, and the boot reaches the terminal's READY line. Two drivers of
   `/services/drivers/` that devmgr creates from no file of the directory are replaced too:
   `virtio-console`, whose device the launch does not attach, with a byte of its declaration note
   flipped, and the directory's copy of `virtio-blk`, whose one device, the boot disk, the boot
   pass binds from its boot module, unsigned. procmgr refuses each at devmgr's verified read
   (`Failed(BodyHash)`, `Parse(Magic)`). On riscv64 the platform description table
   `/config/devmgr/platform/qemu-virt.platform` also has a body byte flipped: procmgr refuses
   devmgr's verified read of it, `Failed(BodyHash)`, and devmgr passes it over and adds no
   platform-table record.
6. `configuration`: a bootloader built under the build's trust store with two more anchors, one
   trusted for every role but configuration and one for configuration alone, and, in
   `/config/svcmgr/services/`, `timed.svc` with a body byte flipped, `pwrmgr.svc` unsigned,
   `crashd.svc` signed by the first anchor's key, and `oomd.svc` by the second's, which signs
   `/services/oomd` as a service too; `entropyd.svc` validly signed over a body other than the one
   the index holds, as an older signed copy is; the directory's index, validly signed, names a
   `removed.svc` the directory lacks and omits the `swapd.svc` it holds; and
   `/config/devmgr/classes/rtc.class` has a body byte flipped. procmgr refuses each configuration
   file at svcmgr's verified read (`Failed(BodyHash)`, `Parse(Magic)`, `Failed(KeyUsage)`) and
   svcmgr reports it passed over; svcmgr refuses `entropyd.svc`, whose body does not match its index
   line; procmgr refuses the service `oomd.svc`'s anchor signs (`Failed(KeyUsage)`); svcmgr reports
   the file the index names but the directory lacks, and the file it does not name; the boot reaches
   the terminal's READY line.
7. `policy-key`: the `configuration` boot's bootloader, and the bundle's policy entry signed in
   the configuration role by the key its store trusts for every role but configuration. The
   bootloader refuses the entry, `Failed(KeyUsage)`.
8. `index`: the indexes of `/config/svcmgr/services/` and `/config/devmgr/classes/` each with a
   body byte flipped. procmgr refuses both (`Failed(BodyHash)`), svcmgr reports that it read no
   recipe and configured no class, and reports every service init registered as one without a
   definition.

A boot passes when every line it owes appears, and fails on any other refusal or fatal line, or at
its deadline. The images are packed again from the sysroot afterwards, whatever the outcome. See
[xtask/README.md § The `signing` case](../xtask/README.md#the-signing-case) for the lines, the
deadlines and the logs. CI runs it in each usertest cell, in the cell's profile.

### Required DMA confinement (`dma-confinement` case)

With the boot policy's `dma-confinement = required`, devmgr gives no driver to a DMA-capable
device no IOMMU unit confines ([device-management.md](device-management.md) § Required DMA
Confinement), which only a boot whose bundle carries that policy shows. `cargo xtask test
dma-confinement [--arch]` (both arches) boots the current sysroot twice, its bundle carrying in
place of the sysroot's policy one that sets `dma-confinement = required`, signed in the
configuration role by the build's key:

1. `absent`: a machine with no IOMMU (`--iommu absent`). devmgr logs that no DMA-capable device
   is given a driver, and refuses each such device's driver, naming the device and the setting;
   with no block device, vfsd mounts no root and the boot stops.
2. `attached`: the default machine, every `virtio-pci` device behind the IOMMU. devmgr refuses no
   device, and the boot reaches the terminal's READY line.

A boot passes when every line it owes appears, and fails on a refusal it does not owe, a DMA
refusal among them, a fatal line, or its deadline. A device that no unit translates beside one that
a unit does, and an IOMMU driver not ready within the settle bound or dead, take the same refusal,
which devmgr's host tests show (`firmware::dma::admits`), since no QEMU machine presents them.
See [xtask/README.md § The `dma-confinement` case](../xtask/README.md#the-dma-confinement-case)
for the lines and the logs. CI runs it in each usertest cell.

### Rollback floor (`rollback` case)

The bootloader keeps the machine's security floor in a boot-services-only UEFI variable
([signing.md](signing.md) § Rollback Floor), which only a boot after another on the same variable
store can show. `cargo xtask test rollback [--arch] [--release]` (both arches) boots the current
sysroot three times on one store, a copy of the firmware's template kept across the three boots,
with the build's trust store floor `F`:

1. `first`: the sysroot's images. The bootloader finds no floor and writes `F`.
2. `raised`: a bootloader built under the build's trust store with the floor `F + 1`, with the
   kernel and every bundle entry signed again at security version `F + 1`. It finds `F` and
   raises the floor to `F + 1`.
3. `older`: the sysroot's images again. The bootloader finds `F + 1` above its store's `F` and
   refuses itself.

A boot passes when every line it owes appears; a boot after a failed one is not made. A firmware
that refuses the write is covered by the bootloader's host tests, since no QEMU firmware refuses
it on demand. See [xtask/README.md § The `rollback` case](../xtask/README.md#the-rollback-case)
for the lines and the logs. CI runs it in each usertest cell, in the cell's profile.

### Root enrolment (`enrolment` case)

The bootloader keeps an enrolled trust store in a boot-services-only UEFI variable and changes it by
the trust requests it finds on the ESP ([signing.md](signing.md) § Trust Store), which only boots
after one another on the same variable store can show. `cargo xtask test enrolment [--arch]` (both
arches) boots the current sysroot six times on one store, a copy of the firmware's template kept
across the six boots, with two local identities `E` and `F` whose roots the build's store does not
trust:

1. `signed`: a request adding `E`'s root, signed for enrolment by the build's identity. The
   bootloader applies it with no one present and boots with `E`'s root enrolled.
2. `unanswered`: an unsigned request adding `F`'s root. The bootloader shows it and asks the
   console; no answer comes, and it refuses the request after 60 seconds and boots.
3. `confirmed`: the same request, answered `yes` at the console. The bootloader applies it.
4. `commit-refused`: an unsigned request revoking the build's roots, with the sysroot's images. The
   kernel would not verify under the store it gives, so the bootloader refuses it before asking.
5. `revoked`: the same revocation signed for enrolment by `E`, with the kernel and every bundle
   entry signed again by `E`. The bootloader applies it, and boots with the build's roots revoked.
6. `holds`: the same request again, with the sysroot's images. The request changes nothing and is
   skipped, and the bootloader refuses the build's kernel.

A boot passes when every line it owes appears; a boot after a failed one is not made. A request past
the enrolled store's bound, a refused write, and a malformed store are covered by the bootloader's
host tests, since no QEMU firmware gives them on demand. See
[xtask/README.md § The `enrolment` case](../xtask/README.md#the-enrolment-case) for the lines and
the logs. CI runs it in each usertest cell.

### Secure Boot (`secureboot` case)

UEFI Secure Boot of the bootloader ([signing.md](signing.md) § Secure Boot) is the firmware's
check, which only a boot can show. `cargo xtask test secureboot [--arch]` (both arches) generates a
development PK, KEK and db, signs the installed bootloader with the db key, and boots the current
sysroot four times, each on a variable store of its own:

1. `enrolled`: the signed bootloader, on the Secure Boot firmware with the three keys enrolled.
   The firmware boots it, and the bootloader logs `boot: Secure Boot: on`.
2. `tampered`: the signed bootloader with a byte of its code flipped, on the same firmware and
   keys. The firmware refuses it.
3. `unsigned`: the bootloader with no signature, likewise refused.
4. `default`: the installed bootloader on the default firmware. The bootloader logs
   `boot: Secure Boot: off`.

The Secure Boot boots run on a firmware pair of their own, since the default pair has no Secure
Boot on x86_64, and on riscv64 has it only on some distributions; CI takes Arch's `edk2-riscv64`
for riscv64 ([build-system.md](build-system.md) § QEMU and Firmware). A firmware that does not
enforce Secure Boot fails the case, naming the firmware, so the case never passes on one that boots
what it should refuse. See
[xtask/README.md § The `secureboot` case](../xtask/README.md#the-secureboot-case) for the lines,
the firmware search and the logs. CI runs it in each usertest cell.

### GDB stub (`debug-port` case)

The GDB stub ([services/gdbstub/README.md](../services/gdbstub/README.md)) debugs a guest process
from a host GDB over the debug port, so its check is a host GDB session.
`cargo xtask test debug-port [--arch] [--port] [--gdb]` (both arches) runs it as the case's second
boot, whatever the first boot's outcome:

1. Stage the `gdb-target` recipe (`services/fixtures/debugger --gdb-target`, a process of two
   threads with an exported counter and tick function;
   [services/fixtures/debugger/README.md](../services/fixtures/debugger/README.md)) from
   `/config/svcmgr/tests/`, and the stub's template from `/config/svcmgr/debug/` naming it, into
   `/config/svcmgr/services/`, and repack the disk images in the layout they have.
2. Boot the current sysroot once with the debug port, and wait for the stub's
   `[gdbstub] attached; serving the debug port` line on the serial stream.
3. Run `gdb -batch` against the port with the target's binary for symbols: list the threads,
   single-step from where the attach stopped the main thread, on text the target attaches shared
   from its binary's image object, break on the tick function and continue to it, read the pointer,
   rewrite the counter and read it back, rewrite a caller-saved register, read it back from the stub
   past GDB's register cache, and restore it, single-step, delete the breakpoint, select the second
   thread and read its registers, and detach. The output must show two threads, a pointer printed
   after the first step, the breakpoint's stop, the rewritten counter and register, a step that
   moved the pointer, the second thread's registers, and GDB's `[Inferior 1 (Remote target)
   detached]`.
4. Wait up to 30 s for the stub's `[gdbstub] detached from gdb-target (crash bindings restored:
   true)` line: procmgr took the target's crash bindings back.
5. Restart the port's driver under the stub: connect again, `qSupported` (the stub attaches to
   the target anew), and kill the `virtio-console` driver through QEMU's gdbstub as
   the case's transport boot does, at the function the stub's reads reach; wait for the stub's
   `[gdbstub] debug port driver at ordinal 1` line once devmgr has restarted the driver, and
   require the session to go on through the restarted driver on the same connection: `?` a stop,
   `Hg1`, the pointer read, and `D`.
6. Kill QEMU, remove both recipes, and repack the images in that layout again, whatever the
   outcome.

It needs a host GDB that debugs the guest architecture (`gdb` built with every target, or
`gdb-multiarch` through `--gdb`). The host computes the verdict and kills QEMU, as for
the case's transport boot, and this boot is part of the same `debug-port` device cell (Coverage
tiers below). See [xtask/README.md § The `debug-port` case](../xtask/README.md#the-debug-port-case)
for the command.

### Interrupts-off wedge (`wedge` case)

The softlockup watchdog's heartbeat cross-checks report a CPU wedged in the kernel with interrupts
masked while another CPU still ticks, and on x86_64 the wedged CPU prints its own frame from the
NMI the observer sends it (see
[scheduling-internals.md § Softlockup Watchdog](../core/kernel/docs/scheduling-internals.md#softlockup-watchdog)).
No harness can make that state: ktest and the other harnesses run in user mode, which cannot mask
interrupts, and the kernel carries no test hooks. `cargo xtask test wedge [--arch]` (both arches)
makes it at the hardware boundary instead, as the `terminal` case injects input, so the production
kernel is what runs:

1. Boot the current sysroot's default boot with QEMU's gdbstub on a unix socket, wait for the
   terminal's `terminal: READY for injection` marker, and read the KASLR slide (`kaslr: slide=`)
   and the hardware id of each logical CPU (the kernel's `smp:` lines) from the serial stream.
2. Stop the VM over the GDB remote serial protocol and read the chosen CPU's program counter. Only
   a CPU whose program counter follows the idle loop's halt instruction (`hlt` on x86_64, `wfi`
   on riscv64), inside the idle loop, is moved: there the idle thread holds no lock. Any other
   state resumes the VM and tries again, up to 100 times.
3. Move the CPU's program counter to the kernel's `halt_loop`, which masks interrupts and halts
   for good, and resume the VM.
4. Wait for the watchdog's report and check it: the detector's line naming the wedged CPU, its
   `=== WATCHDOG:` header, and `=== END WATCHDOG ===`. On x86_64 the wedged CPU's
   `NMI BACKTRACE` frame must come before the observer's line, with its `rip` inside `halt_loop`,
   and the observer's line must end with `own_frame=true`; on riscv64 no frame is printed and the
   line ends with `own_frame=false`.

The command boots twice: the first boot wedges the highest-numbered AP, which the BSP reports, and
the second wedges the BSP, which an AP reports. A gdbstub that cannot be reached, a CPU never found
in the idle halt, or a missing report line fails it. The host computes the verdict and kills
QEMU, as for the `terminal` case. See
[xtask/README.md § The `wedge` case](../xtask/README.md#the-wedge-case) for the command.

In CI it runs as a boot pair inside each `usertest` cell (both arches, both profiles), on the
default boot the cell's `cargo xtask mkdisk` restored.

### CET shadow stacks (`cet` case)

On x86_64 the kernel runs on CET supervisor shadow stacks when the CPU reports them and its
transient-execution selection rewrites no return (it does on a CPU that takes the retpoline
sequence, one without enhanced IBRS, Automatic IBRS or IBRS on entry), so a corrupted return
address faults instead of being followed
([return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)). Neither the CI
runners nor TCG offer the feature, so CI boots only the kernel without them. Every launcher pins the
guest CPU's `cet-ss` property off unless the run asks for it (`--x86-shadow-stack on`), and a QEMU
without the property, the CI image's among them, cannot offer the feature, so no boot
runs on shadow stacks because its host offers them, and these boots are where they are tested. No
harness can corrupt a kernel return address either, and the kernel carries no test hooks.
`cargo xtask test cet` (x86_64) runs both checks under KVM with the guest CPU
`-cpu host,cet-ss=on,enforce`, on a sysroot holding the composed ktest bundle:

1. Boot once and run ktest to its pass marker, with the kernel's `shadow stacks: on` line before
   it.
2. Boot again with QEMU's gdbstub on a unix socket. Once ktest has started, set a hardware
   breakpoint at `syscall::dispatch`, overwrite the return address at the stopped CPU's stack
   pointer at the first hit, which the shadow stack also holds, and resume. The `ret` of that
   `dispatch` must raise `#CP` (vector 21) with error code 1 (`NEAR-RET`) at an address inside
   `dispatch`. A call that does not return leaves no fault, so the host tries again, up to five
   times.

On a host without KVM, or whose CPU or KVM cannot give the guest CET shadow stacks (QEMU then
refuses to start under `enforce`), the command fails, naming what is missing: it never passes
without running the shadow stacks. The host computes the verdict and kills QEMU, as for
the `wedge` case. It is the cet device cell of the local and release host runs (Coverage tiers
below), not a CI boot. See [xtask/README.md § The `cet` case](../xtask/README.md#the-cet-case) for
the command.

A boot whose kernel exception report shows `CR4.CET` set, `SH_STK_EN` clear and a zero interrupt
SSP table address ran on a host that lost the guest's CET state: the kernel writes those registers
once per CPU and never with 0
([return-address-integrity.md](../core/kernel/docs/return-address-integrity.md) § x86-64
Mechanism). On a host that is itself a guest of another hypervisor that state can be lost at run
time (§ Verification Record there). On such a host, by the CPUID hypervisor bit, the run is
inconclusive: the command boots again, up to four runs of each boot, and the boot passes only on
a run without it; four such runs fail the command as inconclusive. On a host that is not a guest
the same report fails the command, as does every other fault.

### Storage roles (`storage-roles` case)

vfsd gives the root and `/esp` to the boot disk alone, and a role on another disk only to the
partition the signed storage statement names ([storage.md](storage.md) § GPT Role-GUID
Discovery); no boot set without a second disk shows either. `cargo xtask test storage-roles
[--arch]` (both arches) boots the default boot set five times with a second disk, each to the
terminal's `terminal: READY for injection` line and swapd's `swap partition:` line, and reads
vfsd's lines: the boot disk it found must be at the location of the boot controller it was told
of, and each of the root, `/esp`, `/data` and swap must be on the disk the boot says:

1. Repack the images in the split-data layout, which stages the statement naming the data and
   swap partitions on `disk-data.img` at the second slot's PCI location, and boot with that image
   on the second slot: the root and `/esp` are on the boot disk, `/data` and swap named by the
   statement on the second disk.
2. Boot the same images with `disk-data.img` at another slot: the root and `/esp` are on the
   boot disk, and `/data` and swap are not taken, vfsd logging that each named partition is not
   on its disk and naming the disk it saw it on, and swapd logging that it has no swap partition.
3. Repack the single image, and boot with a foreign disk on the second slot whose ESP, root, data
   and swap partitions carry priority `0xFFFF`, above the boot disk's, under GUIDs of their own:
   every role is on the boot disk.
4. The same with the foreign disk at the boot disk's priority, where the every-disk search made
   the root lookup a fatal tie: every role is on the boot disk.
5. Boot with a copy of `disk.img` on the second slot, which carries the boot ESP too: the boot
   disk is the one at the boot controller, and every role is on it.

A `no boot disk:` line, a role on another disk than the boot says or taken where the boot says none
is, or a missing line fails the case; the images are repacked in the layout they had, whatever the
outcome. See [xtask/README.md § The `storage-roles` case](../xtask/README.md#the-storage-roles-case)
for the command.

### PCI Express hotplug (`hotplug` case)

devmgr's PCI Express hotplug
([services/devmgr/docs/hotplug.md](../services/devmgr/docs/hotplug.md)), native and through acpid
from the firmware's, runs only when a device arrives in or leaves a hotplug slot, which no boot of
a fixed device set makes, and vfsd's handling of a disk's loss and of its root filesystem's ([vfsd
namespace composition](../services/vfsd/docs/namespace-composition.md#driver-death-and-device-loss)
§ Driver death and device loss) runs only when a disk leaves. `cargo xtask test hotplug [--arch]`
(both arches) makes a device arrive, leave, and arrive again, then makes a disk arrive, in one boot
per hotplug control, and then makes a disk leave and arrive again and a second disk arrive:

1. Stage the [`hotplug-check`](../services/fixtures/hotplug-check/README.md) fixture's recipe from
   `/config/svcmgr/tests/` into `/config/svcmgr/services/`, and the `test-dma` class file from
   `/config/devmgr/tests/` into `/config/devmgr/classes/`, and repack the disk images in the
   layout they have.
2. Boot the current sysroot with two empty `pcie-root-port`s and a QMP control socket, on x86_64
   first under the machine's default, the firmware's ACPI PCI hotplug, whose `_OSC` withholds
   native hotplug control, then under native control (QEMU's ACPI PCI hotplug off, so `_OSC`
   grants it); on riscv64 under native control alone, which the `qemu-virt.platform` key grants once
   devmgr has read the table from the root filesystem. Steps 3 to 7 run in each of these boots.
3. Wait for devmgr's grant line for a slot, `firmware hotplug: _OSC control` under the
   firmware's control and `managed (native control by` under native control (the other one fails
   the boot), and the fixture's `READY for the hot-added device` line.
4. Hot-add QEMU's `edu` device behind the first port (QMP `device_add`), and wait for the fixture's
   `READY for the removal` line: it waits on the `test-dma` class's watch for the `test-dma` driver
   devmgr binds to the added function, then requires the driver's DMA probe to pass and its
   interrupt probe to report an MSI vector delivered.
5. Remove the device (QMP `device_del`) and wait for QEMU's `DEVICE_DELETED` event; then require
   devmgr's removal lines in their order and the fixture's line that devmgr answers `WITHDRAWN` at
   ordinal 0. Under native control `device_del` presses the slot's attention button and QEMU deletes
   the device once devmgr powers the slot off: the lines are the removal started at the end of the
   abort window, the driver's held memory released, one function removed and one driver withdrawn,
   and the slot powered off empty. Under the firmware's, `device_del` makes the firmware's GPE
   method notify an eject request, and QEMU deletes the device once acpid runs the slot's `_EJ0`,
   which it runs only after devmgr's removal job has replied: the lines are the removal started on
   the firmware's eject request, the driver's held memory released, and one function removed and
   one driver withdrawn, and acpid's line that it ran `_EJ0` once devmgr removed one function.
6. Hot-add the device again and wait for the fixture's verdict: the new driver is served at
   ordinal 1, its probes pass, and its IOMMU fault count equals the first device's, so no fault is
   carried across the removal.
7. Hot-add a `virtio-blk-pci` disk over a zero-filled 1 MiB raw image behind the second port (QMP
   `blockdev-add`, then `device_add` with `disable-legacy=on`, `iommu_platform=on` and `vectors=0`,
   behind the IOMMU as a boot disk is, and with no MSI-X vectors), and require, in any order,
   devmgr's `virtio-blk: binds PCI` line, its `virtio-blk: boot tier not granted from the drivers
   directory` line, its `virtio-blk: Wired interrupt, 1 vector(s)` line (the line of the disk's
   `INTx` pin: on x86_64 the one acpid's PIC-model `_PRT` routes, on riscv64 the `virt`
   swizzle's), and the driver's `ready, entering service loop` line: the disk is bound from the
   drivers directory's virtio-blk at the auxiliary tier, as every device unbound after the boot
   pass is, on the wired line the firmware never programmed into it
   ([services/devmgr/docs/hotplug.md](../services/devmgr/docs/hotplug.md#binding) § Binding).
   Kill QEMU.
8. For the storage boots, stage the fixture's disk-mode recipe (`hotplug-check-disk.svc`) alone and
   repack the images in the split-data layout at the block size they have, so the data and swap
   partitions are on `disk-data.img`, named by the storage statement the layout stages on the disk
   at the first port's location, and swapd takes its partition from that disk. Boot under native
   control with that image's `virtio-blk-pci` behind the first port, and wait for devmgr's `managed`
   line and the fixture's `HOLDING a file open on /data` line: vfsd mounted `/data` on the disk at
   startup, and the fixture holds a file open there and knows the root mount's driver by its name,
   `fatfs:/`.
9. Remove the disk with its driver idle, and require devmgr's removal lines, vfsd's
   `disk N: removed; tearing down its mounts` line, and the fixture's `TORN DOWN /data` line: the
   mount is gone, the disk marked removed, the open file stale. Hot-add a copy of
   `disk-data.img`, taken before the boot, behind the second port, and require vfsd's line that
   `/data`'s named partition is not on its disk and is seen on the disk at the second port's
   location: the copy carries the partition the statement names, at a location the statement
   does not name, and takes nothing; a fixture's mount before the data disk is back fails the
   case. Add the disk again on the same block node, and require vfsd's line placing `/data`'s
   named partition on the disk at the first port's location and the fixture's `MOUNTED /data on
   the re-added disk beside the copy of it` line: a fresh `MOUNT` mounts `/data` on it, a disk
   added after start, which the copy beside it does not deny, and the fixture's file, which the
   copy does not hold, reads back ([docs/storage.md](storage.md#gpt-role-guid-discovery) § GPT
   Role-GUID Discovery). Wait for the fixture's verdict: with the root mount's driver stopped a
   lookup at `/` ends in an error within vfsd's bound while `/data` still reads. The fixture
   then kills the root mount's driver; require vfsd's `FATAL: root filesystem lost` line,
   svcmgr's `critical service unrecoverable: vfsd` line, and QEMU's exit.
10. Boot with the boot disk itself behind the first port and the data disk at the second disk's
    slot, which the statement the images are repacked with names, wait for the slot managed and
    the fixture ready, remove the boot disk, and require the same three.
11. Kill QEMU, remove the staged files, and repack the images in their layout again, whatever the
    outcome.

The host computes the verdict and kills QEMU, as for the `terminal` case; the fixture invokes no
shutdown, and the storage boots end in the shutdown svcmgr makes at vfsd's exit. See
[xtask/README.md § The `hotplug` case](../xtask/README.md#the-hotplug-case) for the
command. No canonical CI cell attaches a hotplug port, so the boots are the `hotplug` device cell
of the local and release host runs (Coverage tiers below).

### TPM (`tpm` case)

The TPM 2.0 driver ([services/drivers/docs/tpm.md](../services/drivers/docs/tpm.md)) binds only
on a machine whose firmware reports a TPM, and the reference boot set has none: the CI runners
have no TPM emulator, and a TPM in every boot would make `swtpm` a requirement of every launch.
`cargo xtask test tpm` (x86_64; QEMU's TPM devices sit in the PC Client TPM range, which the
riscv64 `virt` machine does not decode) boots the default boot set twice, each time with a TPM 2.0
backed by an `swtpm` emulator the command starts on a fresh state directory:

1. Boot with QEMU's `tpm-tis` device, the FIFO interface, and wait for the TPM driver's
   `FIFO interface` line, its `first READ answered:` line, and entropyd's
   `entropy contribution accepted:` line naming `hwrng ordinal 0`.
2. Boot again with `tpm-crb`, the CRB interface, and wait for the same lines with
   `CRB interface` in place of the first.

A TPM launch leaves `virtio-rng-pci` out, so the TPM driver is the `hwrng` class's only member, and
the contribution entropyd names can only be the TPM's. Each boot exercises the bootloader's `TPM2`
table seed, devmgr's bind of the `MSFT0101` record, and `TPM2_GetRandom` over the interface, on a
TPM the firmware or, failing it, the driver started. The host computes the verdict and kills QEMU
and the emulator, as for the `terminal` case. See [xtask/README.md § The `tpm`
case](../xtask/README.md#the-tpm-case) for the command. No canonical CI cell attaches a
TPM, so the boots are the `tpm` device cell of the local and release host runs (Coverage tiers
below).

### One shutdown-invoking harness per boot

`svctest` and `usertest` invoke `pwrmgr` shutdown on completion. Two such
harnesses staged together race on shutdown — the slower one may not finish.
Per boot, at most one *shutdown-invoking* harness recipe MUST be staged in
`/config/svcmgr/services/`.

Non-shutdown fixtures may co-stage alongside one harness; svctest's are staged by the fixture sets
above, and each phase below skips, logging the skip line, when the staged set does not declare its
fixture. `crasher` (`restart = always`, never shuts down) and its worker-fault role
(`crasher-worker.svc`, `restart = on_failure`) are in the `ci` set, so their restart paths are
exercised in the services-surface CI cell (svctest's `svcmgr_worker_fault_restart` phase drives the
worker fault, and its `svcmgr_stop_service` phase stops and restarts the fixture through svcmgr's
stop authority), as is its boot-fault role (`crasher-boot.svc`, `restart = on_failure`), whose
instance that finds the token `/data/crasher-boot/die-early`, which the data partition ships,
removes it and dies before its bootstrap request (svctest's `svcmgr_boot_death` phase), and its
one-shot role (`crasher-once.svc`, `restart = never`), whose death svcmgr logs and does not restart
(svctest's `svcmgr_one_shot_death` phase); its bounded faults complete long before `svctest`'s
terminal marker, so the kernel fault dump never clobbers it.
The `memhog` fixture (`memhog.svc`, `restart = on_failure`, `oom_stop = yes`) is in the `ci` and
`burn-in` sets: svctest's `oom_policy` phase has it fill memory until oomd stops it, and its
`logd_reserve` phase has it fill memory while logd is killed and restarted. The `ci`, `burn-in` and
`none` sets stage crashd, so the held-write path of that phase (a child's page fault crashd holds
until oomd's stop frees memory), and the write part of the `memmgr_swap_commit` phase (a child's
commitment past the draw room, its commit overruns held by crashd until write-out to swap opens
memmgr's draw room), run in each of them. The `stopsrc` fixture (`stopsrc.svc`, `restart
= always`, `stop_source = program`) is in both sets: svctest's `svcmgr_stop_service` phase reads
that svcmgr lists it, beside sessiond, as a stop source of the program class and that a job it
started ends with it, and its `oom_policy` phase has it start a job that oomd stops before memhog.
The `oom_policy` phase also opens an operator session whose leader, the `leader` fixture, runs
`/tests/fixtures/programs/crashme oom-hold 512`, a job oomd stops before `stopsrc`'s, and svctest's
`sessiond_operator` phase checks sessiond's operator interface; oomd is a default service, which
every svctest boot stages, and every svctest boot stages sessiond's test recipe in place of its
default one, which names the `leader` fixture (`/tests/fixtures/programs/leader`) as the session
leader. The `reserve-creator` fixture (`reserve-creator.svc`, `reserve = yes`) is in both sets:
svctest's `logd_reserve` phase has it make a `CREATE_FROM_FILE | CREATE_RESERVE` of
`/tests/fixtures/programs/spawn-target` while memhog holds memory critical, which must succeed.

**Test isolation.** The functional harness boots run a controlled substrate:
they drop the autostarted `terminal` (a user-facing program, not part of the
services/programs surface under test). Because `terminal.svc` lives in the
default service set, the harness staging removes it and repacks with
`cargo xtask mkdisk --repack-only` (a normal repack re-mirrors `rootfs/`,
which would restore it); `mkdisk --svctest` and `mkdisk --ubench` remove it with every other recipe
that starts a program. The terminal is exercised in its own boot
(the `terminal` case) and runs in the real default boot. The `crash-endpoint` svctest boot
stages no crashd, so one boot per cell runs the image without the crash
service (see Crash reports above).

CI matrix cells follow these rules per boot. The `usertest` cell boots `usertest` first (via `run
--runs`, terminal dropped), then, after `cargo xtask mkdisk` restores the default boot (terminal
present), `cargo xtask test --cell usertest --lanes 3` runs the cell's cases in three lanes side by
side, each lane on its own copy of the checkout and its cases one after another in the registry's
order ([xtask/README.md § Cells](../xtask/README.md#cells)): the `terminal` case's boot, the
`signing` case's eight boots, the `dma-confinement` case's two boots, the `rollback` case's three
boots, the `enrolment` case's six boots, the `secureboot` case's four boots, the `wedge` case's boot
pair, on x86_64 the `vmgenid` case's save/restore boot pair, the `storage-roles` case's five boots,
and the `shutdown` case's boots, nine on x86_64 (the reboot, the power button and the seven core
deaths) and eight on riscv64. The `ktest` cell's cases are the `kaslr` case's three boots; the
`svctest` cell has none. The terminal and wedge boots have *no* shutdown-invoking harness: the
`terminal` and `wedge` cases compute the verdict host-side and kill QEMU themselves. The reboot
boot's fixture invokes `REBOOT`, the host reads the reset over QMP, and QEMU exits on its own. Each
core-death boot is powered off by the death it makes, read over QMP, and QEMU exits on its own. The
power-button boot is powered off by its press: the host presses the button over QMP, reads the
power-off there, and QEMU exits on its own.

A local run of a cell takes `--lanes` as CI does when the host allows it: each lane's boots are
small boots of the host launch rules
([xtask/README.md § Host launch rules](../xtask/README.md#host-launch-rules)), so `--lanes 3` takes
all three of the host's small-boot places and runs beside no other QEMU, and with `--wait-host` a
lane's boot waits for a place rather than failing. A run that must be alone or timed (`--alone`,
`--timing`), such as the re-run alone of Coverage tiers, takes no lanes and runs its cases one after
another.

---

## Coverage tiers

The matrix CI exercises is exhaustive in three dimensions, over the cells a change owes, and
fixed in the rest. Coverage is tiered so the fixed dimensions still get exercised — just
not on every push.

**Dimension inventory.** Exhaustive per CI run, over the cells its change owes
([conventions.md § CI Gating](conventions.md#ci-gating)): architecture (x86_64,
riscv64) × profile (debug, release) × harness (ktest, svctest, usertest), and the `bench` cell
beside them (release, one CPU and four, under icount; [Benchmarks](#benchmarks-bench-cell)).
Fixed per CI run: vCPU count (4), guest memory (512 MiB), device set
(virtio-blk + virtio-keyboard + virtio-rng + serial + the machine's RTC, the machine's IOMMU
with the virtio-blk, virtio-keyboard, and virtio-rng devices behind it — `intel-iommu` on x86_64,
`riscv-iommu-pci` at 00:01.0 on riscv64 — and, on x86_64, `vmgenid,guid=auto`; the svctest cells
also attach the test devices (`--test-devices`): QEMU's `edu` DMA test device, which svctest's DMA
confinement and MSI forge phases drive, and five `pci-testdev` functions, which its
on-demand-bind phase drives through the test-only test-fault driver; CI boots headless, so no
framebuffer; this is the main set of Driver coverage below; the no-IOMMU boot, `--iommu absent`,
the framebuffer boot, `--display framebuffer`, and the debug-port boots, the `debug-port` case's
two, are device cells (CI's `terminal` case boots, and the `shutdown` case's boots of the targets it
kills through the GDB stub, attach the debug port too, to reach the stub over it), see Device
surfaces, Framebuffer cell, Debug-port cell, and Release host runs below), filesystem (FAT), riscv64
paging mode (sv48 — per-mode runs via `cargo xtask run --riscv-mmu sv39|sv57` are manual, same
posture as CPU-count variations), riscv64 Zkr entropy source (on — runs without it via `cargo xtask
run --riscv-zkr off` are manual, same posture), x86_64 paging depth (4-level — 5-level runs via
`cargo xtask run --x86-paging 5`, under TCG (`SERAPH_ACCEL=tcg`) on a host whose CPU lacks LA57, are
manual, same posture), x86_64 CET shadow stacks (off: the launchers pin `cet-ss=off` on a QEMU that
has the property, and neither the CI runners nor TCG offer them; the boots on them, the `cet` case,
are the cet device cell, see CET cell below, and other boots on them, via `cargo xtask run
--x86-shadow-stack on` under KVM, are manual, same posture), disk logical block size (512 bytes —
the 4Kn boot, a 4096-byte-block image on a 4096-byte-block device, is a storage cell, see Device
surfaces and Disk variations below), and disk count (one — the second-disk boots are storage cells
too). The `virtio-rng` device is a boot-entropy source for the pool seed and KASLR: the firmware's
RNG driver binds it and exposes `EFI_RNG_PROTOCOL`, which the bootloader draws from (OVMF also backs
the protocol with RDRAND on x86_64; on riscv64 the device is the only firmware source under the EDK2
firmware CI boots, and the pool mixes the Zkr `seed` CSR and jitter besides; see
[core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)). A driver or filesystem joins the
default boot set, and with it the canonical cells, only by replacing the main device of its type
(Driver coverage below); any other driver adds cells to its own device surface, and variants belong
to the tiers below.

| Tier | Where | When | Coverage |
|---|---|---|---|
| Canonical | `build-test.yml` | every push / PR: the cells its change owes ([conventions.md § CI Gating](conventions.md#ci-gating)) | full arch × profile × harness at the fixed defaults, and the `bench` cell (Cells below) |
| Burn-in | `burnin.yml` | tag push; manual dispatch on any ref | each canonical arch × profile × harness `run --runs` boot × 20 iterations, 2-way parallel (no `crasher` co-staging, `memhog`, `reserve-creator` and `stopsrc` co-staged in the svctest cell, no `cargo xtask test` case or cell boots), and every bounded proof (`cargo xtask kani`, [Bounded verification](#bounded-verification)) |
| Local host runs | developer host, commands below | REQUIRED for a PR whose own diff changes the CPU-count surface, the memory surface, or a device surface, or that states a concurrency-fix purpose as Repeat count defines it and makes a non-inert change (see Boundary surface, Memory surface, Device surfaces, and Repeat count below; a stated concurrency-fix purpose owes the boundary set on its own), once per PR (see When the runs are owed below) | CPU-count and memory variations CI runners cannot reach, and the device cells CI does not boot |
| Release host runs | local host, commands below | before each tag, on the commit to be tagged or an earlier one with the bump and a documentation- or comment-only change since | every boundary below (riscv64 16 and 128 harts; x86_64 16 and 128 vCPUs) once in the debug profile and once in the release profile, and the memory variation, the large-memory cell, and every device cell (the disk variations, the no-IOMMU variant, the framebuffer cell, the debug-port cell, the hotplug cell, the CET cell, and the TPM cell) once, and every bounded proof, whatever the release's PRs touched, and the fuzz campaign, a manual dispatch of `fuzz.yml` (see Release host runs below) |

**Cells.** A cell is one launch configuration and the boots made on it; each differs from every
other cell in that configuration, which is why it stands alone. The table states every cell, its
tier, and what it alone covers; the paragraphs below and [Gating](#gating) give each one's
commands, staging, and budget. Its Cases column lists the `cargo xtask test` cases the cell runs, as
the case registry assigns them ([xtask/README.md](../xtask/README.md#cases)), a case on fewer
architectures than its row's carrying them after its name: `cargo xtask lint-docs` fails when a
registered case is missing, listed in another cell, or listed on other architectures than the
registry runs it on (its `md-test-cells` rule).

| Cell | Tier | Architectures | Launch | Cases | Covers |
|---|---|---|---|---|---|
| `svctest` | Canonical | x86_64, riscv64; debug, release | the main set with the test devices (`--test-devices`); svctest staged with its fixtures (`crasher`, `crasher-worker`, `crasher-boot`, `crasher-once`, `memhog`, `reserve-creator`, `stopsrc`), crashd's test recipe and oomd's test recipe | none | the services harness: the main set's drivers and the test devices, DMA confinement and MSI delivery, the filesystem, the restart, out-of-memory, and stop-source paths its fixtures drive, and the crash reports of its boot ([Crash reports](#crash-reports)) |
| `usertest` | Canonical | x86_64, riscv64; debug, release | the main set; usertest staged; vfsd at debug (`mkdisk --log-levels`) | `terminal`, `signing`, `dma-confinement`, `rollback`, `enrolment`, `secureboot`, `wedge`, `vmgenid` (x86_64), `storage-roles`, `shutdown` | the programs surface, a boot with no crash report ([Crash reports](#crash-reports)), the delivery of log levels ([Log levels](#log-levels-usertest-cell)), and what each case covers (Gating) |
| `ktest` | Canonical | x86_64, riscv64; debug, release | the composed ktest bundle with the `mapredo` knob | `kaslr` | the kernel tests, the bootloader's redo of steps 6 and 7 ([Steps 6 and 7 redo](#steps-6-and-7-redo-ktest-cell)), and KASLR |
| `bench` | Canonical | x86_64, riscv64; release | the bench-only ktest bundle, then the init image with ubench staged and a framebuffer, each under icount (`--icount`), at 1 CPU (three runs) and 4 CPUs (one) | none | each kernel and userspace benchmark's instruction count against its baseline ([Benchmarks](#benchmarks-bench-cell)) |
| boundary | Local and release host runs | x86_64, riscv64; debug, and release at release runs | the ktest bundle at 16 and at 128 CPUs | none | the CPU-count surface (Boundary surface below) |
| memory | Local and release host runs | x86_64 or riscv64; debug | the current sysroot at 4 CPUs and 1024 MiB | none | the memory surface (Memory surface below) |
| large-memory | Release host runs | x86_64, riscv64; debug | svctest staged as the canonical svctest cell stages it, at 4 CPUs and 8192 MiB | none | svctest's phases past the RAM sizes at which a RAM-proportional cost overtakes a fixed margin, and RAM-sized byte counts past 2^32 (Large-memory cell below) |
| 4kn | Local and release host runs | x86_64, riscv64; debug | svctest from a 4Kn disk (`mkdisk --block-size 4096`) | none | 4096-byte logical blocks (Disk variations below) |
| second-disk | Local and release host runs | x86_64, riscv64; debug | svctest with `/data` and swap on a second disk (`mkdisk --split-data`, `--second-disk`) | none | the data and swap partitions on their own disk, named by the storage statement |
| shared-line | Local and release host runs | x86_64, riscv64; debug | as second-disk, both disks on one `INTx` line (`--second-disk-shared-line`) | none | two virtio-blk devices served on one interrupt line |
| oversize-block | Local and release host runs | x86_64, riscv64; debug | svctest with a second disk at 8192-byte blocks (`--second-disk-block-size 8192`) | none | the refusal of a disk above virtio-blk's largest block size |
| no-iommu | Local and release host runs | x86_64, riscv64; debug | svctest with the IOMMU detached (`--iommu absent`) | none | devmgr's unconfined path (Release host runs below) |
| framebuffer | Local and release host runs | x86_64, riscv64; debug | svctest with QEMU std VGA and no window (`--display framebuffer`) | none | the framebuffer driver (Framebuffer cell below) |
| debug-port | Local and release host runs | x86_64, riscv64; debug | the debug port's `virtio-console` device | `debug-port` | the virtio-console driver, the debug port, and the GDB stub (Debug-port cell below) |
| hotplug | Local and release host runs | x86_64, riscv64; debug | two empty PCI Express root ports | `hotplug` | PCI Express hotplug (Hotplug cell below) |
| cet | Local and release host runs | x86_64; debug | KVM on CET shadow stacks, the ktest bundle | `cet` | CET shadow stacks (CET cell below) |
| tpm | Local and release host runs | x86_64; debug | a TPM 2.0 backed by `swtpm`, behind `tpm-tis` then `tpm-crb` | `tpm` | the TPM driver (TPM cell below) |

**Why local-only.** Hosted CI runners are ~4-vCPU TCG-only machines; a
16-vCPU guest is a ~4× thread oversubscription and a 128-vCPU guest a
~32×. High `-smp` coverage is local by design, not an oversight. The local
host runs below are procedurally REQUIRED for the PRs that owe them, and the
release host runs for each tag — binding the same way the
[pre-merge review](conventions.md#branch-and-pr-workflow) is, with no CI
surface.

**Driver coverage.** Every driver is covered in one of three tiers.

- **Main set.** The devices of the QEMU machine the canonical and boundary boots use (`q35` on
  x86_64, `virt` on riscv64), one per device type a boot needs, each the device of that type with
  the broadest QEMU support on both machines that the system or its firmware drives (a VirtIO PCI
  device where the system has a VirtIO driver of the type, or, for a type only the firmware
  drives, where the firmware has one; else the machine's built-in device), and the filesystem the
  boots mount. Each entry names the cells that exercise
  it, all of them canonical:
  - block: `virtio-blk-pci`, through the virtio-blk driver, which every svctest and usertest cell
    reads its disk through;
  - console: the machine's 16550-compatible UART (COM1 on `q35`, the NS16550 on `virt`), through
    the serial driver: the output of every svctest and usertest boot, and the serial receive round
    of the `terminal` case;
  - input: `virtio-keyboard-pci`, through the virtio-input driver: the keyboard and input
    restart rounds of the `terminal` case, and svctest's input checks (the drivers phase's input
    case and the devmgr phase's input ordinal);
  - entropy: `virtio-rng-pci`, which the firmware's RNG driver drives first, and from which the
    bootloader draws the pool seed and the KASLR words through its `EFI_RNG_PROTOCOL`: the
    `kaslr` case's boots of the ktest cells, and svctest's random phase; and at run time through the
    virtio-rng driver: svctest's hwrng checks (the drivers phases' hwrng read, restart, deny, and
    stray-cap cases);
  - DMA confinement: the machine's IOMMU (`intel-iommu` on `q35`, `riscv-iommu-pci` on `virt`),
    through the iommu-vtd and iommu-riscv drivers: svctest's DMA confinement phase, and, for the
    message writes the riscv-iommu translates, its MSI delivery and MSI forge phases;
  - clock: the machine's RTC (the CMOS RTC on `q35`, the Goldfish RTC on `virt`), through the
    cmos-rtc and goldfish-rtc drivers: svctest's timed phases (the wall clock, and timed's
    resolve of the RTC driver restarted);
  - filesystem: FAT16, through the fatfs driver, on the partitions `mkdisk` formats (the ESP, root
    and data partitions, each FAT16 at its size; the swap partition is raw and no fatfs serves
    it): svctest's filesystem phases;
  - and the devices the harnesses drive, which only the svctest launches attach
    (`--test-devices`): QEMU's `edu`, which the test-only test-dma driver drives in svctest's DMA
    confinement and MSI delivery, forge, churn, and release phases, five `pci-testdev` functions,
    which the test-only test-fault driver serves in svctest's on-demand-bind phase, and, on x86_64,
    `vmgenid`, the generation source the kernel's snapshot detection reads: the `vmgenid` case.

  The canonical boots are headless, so the main set holds no framebuffer. Every code PR's CI cells
  boot the main set. A driver joins it only by replacing the main device of its type; any other
  driver adds cells to its own device surface (Device surfaces below), not to the main set.
- **Tag set.** The main set and every driver with a QEMU-testable device, filesystem drivers
  included, each through its cells: the release host runs boot every device cell before each tag
  (Release host runs below), and burn-in repeats the canonical cells. The framebuffer driver's
  device, QEMU std VGA, is outside the main set because the canonical boots are headless; the
  framebuffer cell (Framebuffer cell below) boots it. The virtio-console driver's device, the debug
  port, is outside it because only a launch that asks for a debug port attaches it: the
  debug-port cell (Debug-port cell below) boots it, and in CI the `terminal` case's boots and
  the `shutdown` case's GDB-stub boots attach it to reach the stub over it. The TPM driver's
  device, a TPM 2.0 behind QEMU's `tpm-tis` or `tpm-crb` and backed by `swtpm`, is outside it
  because only the `tpm` case attaches it; the tpm cell (TPM cell below) boots it.
- **Hardware only.** A driver whose device QEMU cannot present has no QEMU cell in either set; its
  README documents a hardware test procedure, and it is exercised on real hardware by that
  procedure. No in-tree driver is in this tier.

**Inert changes.** A change that alters only the following cannot change behaviour at any CPU count,
memory size, or device set, and owes no local host run of this section, whatever file it is in (a
new or changed proof harness still owes its local sizing, § Bounded verification):

- Markdown, and comment lines in source files, build scripts, and linker scripts;
- lint attributes: `#[allow(...)]`, `#[expect(...)]`, `#[warn(...)]`, `#[deny(...)]`, their inner
  `#![...]` forms, and a `#[cfg_attr(<predicate>, <lint attribute>)]`;
- code compiled only for host tests, proofs, or fuzzing: a module or item under `#[cfg(test)]`,
  `#[cfg(kani)]`, `#[cfg(fuzzing)]`, or a `#[cfg(any(...))]` of no predicate but `test`, `kani`,
  and `fuzzing` (§ Fuzzing), a `#[test]` function, or an attribute applied only under `cfg(kani)`
  (`#[cfg_attr(kani, ...)]`, § Bounded verification);
- checked-in fuzz inputs: the files under a crate's `fuzz/` directory (§ Fuzzing), which only its
  replay test and its fuzz target read;
- the deletion of a named function, constant, static, or type (not an `impl` block or a
  trait-method implementation; a module is the next item) that nothing names at the PR head
  outside comments and Markdown (`git grep -w <name> <head>` finds no other use) and that carries
  no attribute making it reachable without its name (`no_mangle`, `export_name`, `used`,
  `link_section`, `global_allocator`, or `panic_handler`, in any form: plain, `unsafe(...)`, or
  under `cfg_attr`);
- the deletion of a whole module, its source file or its inline `mod` block, that nothing names
  at the PR head outside comments and Markdown (`git grep -w <module> <head>` finds no other use),
  when its lines name an item the surfaces below list only to use it (pass, match, or construct
  its value) and define none of them, no surface below lists its file or a directory that holds
  it, none of its items carries one of the attributes the item above lists, it defines every type
  an `impl` block in it implements for, and it holds no `global_asm!` or `naked_asm!` invocation.
  A crate root and a build script, which Cargo reaches without a name, are not such a module, and
  any other changed line in a file that remains, the declaration that named the module included,
  is judged on its own.

**Identical images.** A PR whose own diff (When the runs are owed below) leaves every file
`cargo xtask build` installs identical, in every part a loader reads, on both architectures and in
both profiles, changes nothing a boot runs: every line of its own diff outside the host side named
below is inert.
The evidence is `cargo xtask compare-images`
([xtask/README.md](../xtask/README.md#cargo-xtask-compare-images)), never a comparison made by
hand. It builds the PR's merge base and its head in one scratch worktree and compares each
installed file: an ELF image by its loader-relevant header fields, its program headers and the
bytes of its `PT_LOAD` segments, and its allocated sections and note sections (the loaders read a
`.note.seraph.*` section by name); a PE image by its headers and sections, its link time stamps and
its debug directory aside; in both, the descriptor of a GNU build-id note aside, since the linker
computes the id over the symbol tables and debug information too; the bootloader bundle by its
entries; and any other file by its bytes.
Its verdict line names both commits and the four cells (x86_64 and riscv64, each debug and
release), and only `IDENTICAL` over all four makes the lines inert. The host side is judged as the
rest of this section judges it, verdict or not: every line under `xtask/`, and every line of a crate
xtask's build compiles in (each in-tree crate of the `[dependencies]` of `xtask/Cargo.toml`, and
each in-tree crate those depend on, such as `shared/gdb-rsp/`). The launchers, the disk tooling, and
the host-driven tests run on the host, outside every image, and the device surfaces below list items
of them, so identical images are no evidence about them. The verdict does not cover:

- a build that is not reproducible: two builds of one commit that differ make the command report a
  difference, so a PR loses the class but never claims it wrongly;
- a later head whose changes alter an image: a verdict at head H covers a later head M only when
  the PR's own diff makes the same changes at H and at M apart from changes the list above makes
  inert, and otherwise the command is run again at M, or the PR owes what its non-inert lines owe;
- what no loader reads: the symbol tables, the debug information, and the size of a file, which
  can move where the bootloader and procmgr place later data but no byte a loaded image holds.

A PR whose changes outside Markdown are all inert owes no local host run of this section, whatever
purpose it states. The surfaces below, and Repeat count, are judged on the non-inert lines only.

**Boundary surface.** The boundary set below is owed when, and only when, the PR's own diff (see
When the runs are owed below) makes a non-inert change to the CPU-count surface; a stated
concurrency-fix purpose owes the whole boundary set on its own (see Repeat count below). The
CPU-count surface is the code that fixes the CPU-count width, enumerates and brings up CPUs, sizes
per-CPU storage, or signals across CPUs, and it is exactly what this paragraph lists. Code that only
reads `CPU_COUNT` or a `cpu_count` argument to iterate over CPUs is not on it unless it lies in a
whole-surface file, names a listed item, lies within one's definition, or is a test case whose
work grows with the CPU count (below); the rules of [coding-standards.md](coding-standards.md)
§ CPU-Count Width and the release host runs cover it. The surface is these files as a whole:

- `core/kernel/src/cpu_mask.rs` (the CPU mask type and its width);
- `core/kernel/src/percpu.rs` (per-CPU data and its slabs);
- `core/kernel/src/arch/x86_64/ap_trampoline.rs` and `core/kernel/src/arch/riscv64/ap_trampoline.rs`
  (AP and hart bringup);
- `core/kernel/src/mm/tlb_shootdown.rs` (the TLB-shootdown broadcast);
- `core/kernel/src/mm/tag_allocator.rs` (the per-CPU address-space tags, whose count it fits to
  the CPU count);

and, in any other file, a line that adds a structure with one entry or one bit per CPU, a line
that adds or changes a test case whose work grows with the CPU count (a ktest or svctest case
that runs a step, or spawns a thread, for each CPU), and a changed line that names one of these
items as a whole identifier or lies within one's definition (its attributes, signature, fields,
or body):

- CPU-count width: `MAX_CPUS`, `AtomicCpuMask`, `MaskSource`, `mask_words`, `set_boot_cpu_count`;
- per-CPU storage: `alloc_zeroed_slab` and the page count it takes (`slab_pages`); the per-CPU
  slab descriptor `PerCpuSlab`, whose `bytes` gives each per-CPU slab's byte count, every constant
  of that type (each slab's descriptor, which names the type), and `alloc_per_cpu_slab`, which
  allocates a slab from its descriptor; the definition of every function that calls
  `alloc_per_cpu_slab` or `alloc_zeroed_slab` (the per-CPU storage initialisers; a call to one is
  on the surface only when it names another listed item, as a call to an `init_ap_*` initialiser
  does), except `frame_map::init` and `init_cspace_registry`, which size RAM tables through
  `alloc_zeroed_slab` and are on the memory surface instead; every `init_storage` and
  `init_per_cpu_storage`, which take the boot CPU count and size per-CPU storage from it (a call to
  one names it, so a change to the count it passes is on the surface); `kernel_reserve_pages` (the
  CPU-scaled kernel reserve); and the element types of the per-CPU arrays and slabs, today
  `PerCpuData`, `PerCpuScheduler`, `ThreadControlBlock` (through `MaybeUninit`), `TssWithIopb`,
  `TagState`, `CpuRng`, `Acc`, `Sample`, `CpuDiag`, `TlbShootdownRequest`, `VectorRow`,
  `SlotEntry` (the riscv64 IMSIC identity rows, and each `VectorRow`'s entries), `DeliveryGate`,
  `CoreSlot` (the per-CPU core key and index of the SMT topology), and `SyscallScratch` (the
  per-CPU syscall scratch buffer)
  (`git grep -n -E 'alloc_(zeroed|per_cpu)_slab::<|; MAX_CPUS\]' <head>` lists the arrays and
  slabs, and also the slabs that are not per-CPU: the single-slot entropy pool, the tag pool, and
  the RAM-sized chunk tables of `frame_map::init` and `init_cspace_registry`). A change that
  alters an element type's size is on the surface whether it edits the type's own fields or a type
  or constant the element holds by value (for example `RunQueue` and `NUM_RUN_QUEUES` inside
  `PerCpuScheduler`, or `Prng` inside `CpuRng`), and so is a change to a constant that sizes a
  per-CPU allocation (`KERNEL_STACK_PAGES` for the idle stacks, and `TAG_STATE_BYTES`, the tag-state
  slab's element size);
- CPU enumeration and bringup: in the bootloader, `parse_cpu_topology`, `parse_madt_topology`
  and the MADT walk behind it (`madt_topology`, `madt_cpu_ids`, and the per-CPU
  `record_cpu_id`), `place_cpu_ids`, `parse_cpu_count` and `place_hart_ids`, the sizing of the
  CPU-id array (`cpu_topology_capacity`, `cpu_id_capacity`, and `allocate_cpu_ids`),
  `step5_discover_cpu_topology`, `CpuTopology`, `discover_boot_hart_id` and `bsp_hardware_id`
  (the source of the BSP id that becomes `cpu_ids[0]`), and the handoff of the count and the CPU
  ids into `BootInfo` (`cpus.count` and `cpus.ids_phys`); in the kernel, the boot CPU count and
  ids (`info.cpu_count`,
  `boot_cpu_count`, and `boot_cpu_ids`, which reads the ids in place), `start_ap`,
  `sbi_hart_start`, `kernel_entry_ap`, every `init_ap`, and the `init_ap_*` per-CPU storage
  initialisers;
- IPI send and receive: `send_wakeup_ipi`, `send_tlb_shootdown_ipi`, `send_init_ipi`, `send_sipi`,
  `send_nmi_to`, `sbi_send_ipi_to`, `sbi_hart_mask`, `wait_for_ack`, `IpiWaitCtx`, the
  NMI backtrace request and the watchdog's wait for it (`nmi_backtrace_request`,
  `request_nmi_backtrace`, `dump_remote_frame`, `NMI_BACKTRACES_PRINTED`, and
  `REMOTE_FRAME_BUDGET_US`), the
  `IPI_VECTOR_*` constants, the x86_64 `ipi_*` stubs and handlers in `idt.rs`, the x86_64 ICR and
  x2APIC primitives and the mode they set (`apic_send_icr`, `wait_icr_idle`,
  `enable_x2apic_this_cpu`, `X2APIC_ENABLED`, `x2apic_supported`, `x2apic_enabled`,
  and `x2apic_wrmsr_fence`), `ICR_IDLE_BUDGET_US`, the bounded-wait helpers the ack and ICR
  waits run on (`WaitTimer`, `spin_until`, and `MAX_SPINS_PER_UNIT`), the riscv64
  `handle_software_interrupt`, and `sync_instruction_fetch`, which on riscv64 asks every hart for a
  `fence.i` through SBI RFENCE;
- the TLB-shootdown broadcast: `shootdown`, `shootdown_range`, `service_shootdowns`,
  `shootdown_remote`, and `needs_remote_shootdown`.

A changed line that only uses a listed type is not on the surface: an import of it, a signature
or type annotation that names it, a read or write of one of its fields, or a call of one of its
methods, where the line changes neither the type's fields or size, nor a structure with one
entry or one bit per CPU, nor how such a structure is sized or indexed. The listed types are
`AtomicCpuMask`, `MaskSource`, `PerCpuSlab`, `CpuTopology`, `IpiWaitCtx`, `WaitTimer`, and the
element types of the per-CPU arrays and slabs. A line that names any other listed item, or that
lies within a listed item's definition, stays on the surface.

A change anywhere else, however close to the scheduler or the SMP paths, is off the surface. The
release host runs (Release host runs below) boot every boundary before each tag and are the
backstop for a scaling defect this surface misses. A boundary set MAY also be run for a PR that
does not owe it, when whoever coordinates the work (the orchestrator of a batch, or the
maintainer) judges that the change warrants it; nothing schedules such a run, and the PR body
reports it as a run the PR does not owe (Hangs at oversubscription below). A PR that adds an
item of the kinds above that names none of the listed items MUST add it to this list.
`cargo xtask lint-docs` fails when a name this list, the memory and device surfaces' lists, or
their screens state no longer names code, a tracked file, or a tracked directory (its
`md-coverage-symbols` rule, [xtask/README.md](../xtask/README.md#cargo-xtask-lint-docs)), so a
PR that renames or deletes a listed item updates the list in the same change. The commands below
screen a diff for the surface. The first lists the whole-surface files the diff changes. The
second prints every file header of the diff and every line, changed or context, that names a
listed item; `-W` widens each hunk to its whole enclosing item, so a change inside a listed
item's definition prints that item's name. Each printed name is a candidate: the PR owes the set
when a non-inert changed line names the item or lies within its definition, read in that file's
hunk, unless the line only uses a listed type as the paragraph above defines it. A printed
`alloc_per_cpu_slab` or `alloc_zeroed_slab` call is a candidate for the initialiser that
encloses it (except `frame_map::init` and `init_cspace_registry`, which the memory surface
covers): the set is owed when a non-inert changed line lies within that function, read in the
widened hunk. The screen finds named items and changes inside their definitions; it does not
follow a size change through a nested type or a sizing constant, so a diff that changes a
struct's fields or a constant's value is also read against the per-CPU storage bullet
(`git grep -n -w <name> <head>` shows where the type or constant is held). The screen does not
find a test case whose work grows with the CPU count either: a diff that adds or changes a ktest
or svctest case is read for one. A diff for which neither command prints a candidate, that adds
no per-CPU structure and no such test case, and whose type and constant changes reach no per-CPU
element or allocation is off the surface.

```sh
B=$(git merge-base <head> origin/master)
git diff --stat "$B" <head> -- core/kernel/src/cpu_mask.rs core/kernel/src/percpu.rs \
    core/kernel/src/mm/tlb_shootdown.rs core/kernel/src/mm/tag_allocator.rs \
    'core/kernel/src/arch/*/ap_trampoline.rs'
S='MAX_CPUS|AtomicCpuMask|MaskSource|mask_words|set_boot_cpu_count|alloc_zeroed_slab|slab_pages'
S="$S|init_storage|init_per_cpu_storage"
S="$S|PerCpuSlab|alloc_per_cpu_slab"
S="$S|kernel_reserve_pages|boot_cpu_count|PerCpuData|PerCpuScheduler|ThreadControlBlock"
S="$S|TssWithIopb|TagState|CpuRng|Acc|Sample|CpuDiag|TlbShootdownRequest|VectorRow|CpuTopology"
S="$S|SlotEntry|DeliveryGate|SyscallScratch|CoreSlot"
S="$S|parse_cpu_topology|parse_madt_topology|madt_topology|record_cpu_id|parse_cpu_count"
S="$S|madt_cpu_ids|place_cpu_ids|place_hart_ids|cpu_topology_capacity|cpu_id_capacity"
S="$S|allocate_cpu_ids|cpus\.count|cpus\.ids_phys|info\.cpu_count|boot_cpu_ids"
S="$S|step5_discover_cpu_topology|start_ap|discover_boot_hart_id|bsp_hardware_id"
S="$S|sbi_hart_start|kernel_entry_ap|init_ap(_[a-z_]+)?|send_(wakeup|tlb_shootdown|init)_ipi"
S="$S|send_sipi|send_nmi_to|sbi_send_ipi_to|sbi_hart_mask|wait_for_ack|IpiWaitCtx"
S="$S|nmi_backtrace_request|request_nmi_backtrace|dump_remote_frame|NMI_BACKTRACES_PRINTED"
S="$S|REMOTE_FRAME_BUDGET_US"
S="$S|IPI_VECTOR_[A-Z_]+|ipi_[a-z_]+_(stub|handler)|apic_send_icr|wait_icr_idle"
S="$S|enable_x2apic_this_cpu|X2APIC_ENABLED|x2apic_supported|x2apic_enabled"
S="$S|x2apic_wrmsr_fence|ICR_IDLE_BUDGET_US|WaitTimer|spin_until|MAX_SPINS_PER_UNIT"
S="$S|handle_software_interrupt|sync_instruction_fetch"
S="$S|shootdown(_range|_remote)?|service_shootdowns|needs_remote_shootdown"
git diff -W "$B" <head> -- . ':(exclude)*.md' | grep -E "^\+\+\+ |\b($S)\b"
```

The boundary set is every boundary CPU count below, each once (`--runs 1`, as Repeat count
says): 16 and 128 CPUs on both architectures, riscv64 16 and 128 harts and x86_64 16 and 128
vCPUs. No run is wider than 128 CPUs, on either architecture: the 256- and 512-vCPU runs are removed
from every set by the maintainer's decision on
[#694](https://github.com/kottlerg/seraph/issues/694), since the 512-vCPU run (the old
`MAX_CPUS`) took most of an hour and saturated the host, and today's `MAX_CPUS` (8192) is past
any local host's reach; Known
boundaries below states what covers the widths past 128. Every run saves its log for the timing
report below (`--save-logs`).

```sh
# Boundary CPU counts, riscv64 (TCG on the 16-core reference host: the 16-hart
# run, at 1x, takes ~50 s; the 128-hart run ~340 s at 8x hart
# oversubscription; each budget is for HANG classification, see below):
T=target/xtask/ktest-timing
cargo xtask build --arch riscv64
cargo xtask mkdisk --harness ktest --arch riscv64
cargo xtask run --arch riscv64 --cpus 16 --runs 1 --timeout 180 \
    --save-logs $T
cargo xtask run --arch riscv64 --cpus 128 --runs 1 --timeout 1140 \
    --save-logs $T

# Release-profile boundary boots, riscv64 (release host runs only, once each;
# the same-architecture rebuild needs no clean, only an architecture switch
# does; no timing logs are saved because the baselines below are debug-profile;
# the memory variation below runs on whatever sysroot is current, so it
# follows a debug-profile build, never the release boots above it):
cargo xtask build --arch riscv64 --release
cargo xtask mkdisk --harness ktest --arch riscv64
cargo xtask run --arch riscv64 --cpus 16 --runs 1 --timeout 180
cargo xtask run --arch riscv64 --cpus 128 --runs 1 --timeout 1140

# Boundary CPU counts, x86_64 (KVM on the 16-core reference host: the 16-vCPU
# run, at 1x, takes ~40 s; the 128-vCPU run, at 8x vCPU oversubscription,
# ~57 s, since idle vCPUs halt; each budget is for HANG classification, see
# below):
cargo xtask clean
cargo xtask build
cargo xtask mkdisk --harness ktest
cargo xtask run --arch x86_64 --cpus 16 --runs 1 --timeout 180 \
    --save-logs $T
cargo xtask run --arch x86_64 --cpus 128 --runs 1 --timeout 900 \
    --save-logs $T

# Release-profile boundary boots, x86_64 (release host runs only, as above):
cargo xtask build --release
cargo xtask mkdisk --harness ktest
cargo xtask run --arch x86_64 --cpus 16 --runs 1 --timeout 180
cargo xtask run --arch x86_64 --cpus 128 --runs 1 --timeout 900

# Timing report (report only; see below):
B=xtask/baselines/ktest-timing
for a in riscv64 x86_64; do
    cargo xtask ktest-timing --base $T/$a-16cpu-1.log --wide $T/$a-128cpu-1.log
done
for w in riscv64-16 riscv64-128 x86_64-16 x86_64-128; do
    cargo xtask ktest-timing --baseline $B/${w}cpu.txt $T/${w}cpu-1.log
done
```

The release-profile boots, which only the release host runs make, reuse the debug budgets
provisionally, since no release boot time has been measured at these widths; a release run that
outlives one is a HANG to be examined, and its measured time re-derives the budget. Each debug
budget is the larger of three times the measured run and the measured run plus the longest failing
bound ktest stretches at that width
(`split_delete_race`'s 100 s exit poll, through `scaled_polls`: 100 s at 16 CPUs, 800 s at 128),
rounded up to a minute, so a stuck cell reaches its own FAIL line before `run --runs` classifies
the run as a HANG. A change to the measured runs or to the longest stretched bound re-derives the
budgets.

The two 16-CPU runs are the 1x width the scaling below starts past (`UNSCALED_CPUS`, the reference
host's core count) and each architecture's base for the timing report's cross-width comparison.
The two 128-CPU runs are the widest, two full mask words at 8x oversubscription; 128 harts is also
the count at which hart-scaled firmware allocations once collided with the kernel image's load
address ([#377](https://github.com/kottlerg/seraph/issues/377)). The partial-word mask paths, a
count past one 64-bit word that does not fill the next, are host-tested rather than booted (Known
boundaries below).

Past 16 CPUs ktest stretches the wall-clock bounds
[core/ktest/README.md § Tier S](../core/ktest/README.md#tier-s--srcstress) lists by the
oversubscription factor the width implies, so a slow step at a boundary run is not taken for a
stuck one while the CI widths keep the tight budgets; its stress cells make their full attempt
counts at every width.

**Timing report.** The stretched bounds assume that a cell's cost grows at most linearly with the
width; the boundary runs measure it. `cargo xtask ktest-timing`
([xtask/README.md](../xtask/README.md#cargo-xtask-ktest-timing)) reads the saved logs and reports,
per tier and per cell, the wall time between the stamps ktest prints (a cell's start line and its
`PASS` or `FAIL` line), with the boot to ktest's start, ktest's span, and the host's wall time for
the run below them. Across widths it reports, per architecture, the 16- and 128-CPU times, their
ratio `R`, and `R/F`, the ratio over the width factor `F` (8). Within a width it compares each log
with the baseline of its architecture and width under `xtask/baselines/ktest-timing/`, whose header
records the commit and the reference host's CPU, kernel, QEMU, and accelerator settings (KVM's
module parameters on x86_64), and warns when the host running the comparison differs. A row is
flagged when `R/F`, or its ratio to the baseline, exceeds 1.5 and its time exceeds the expected one
(`F` times the base, or the baseline's) by at least 1 s; the cells are listed by that ratio, highest
first. Every cell makes the same attempts at both widths, so `R` is the growth of the cell's whole
cost. The report is a report, not a gate: a PR that owes the boundary set carries it in its body,
and no flag blocks a PR or a tag until the threshold is calibrated against the baselines and made a
gate. A baseline is rewritten on the reference host: from runs at a `master` commit when the host's
QEMU, kernel, or accelerator settings change, and by the PR that changes a cell's cost on purpose,
from runs at a commit of that PR whose boot-image code (the `ktest-commit` of
[xtask/README.md](../xtask/README.md#cargo-xtask-ktest-timing)) is the code its merge brings to
`master`, taken again when `master` changes that code before the merge.

**Memory surface.** The memory variation below is owed when, and only when, the PR's own diff makes
a non-inert change to the memory surface: the code that sizes or maps physical memory by the guest's
RAM, exactly as listed here. It is `core/kernel/src/mm/buddy.rs` and `core/kernel/src/mm/init.rs` as
a whole, and, in any other file, a changed line that names, or lies within the definition of, one of
these items: the boot memory map and the direct map (`translate_memory_map`, `max_ram_address`,
`direct_map_ceiling`, `compute_max_physical_address`, `init_kernel_page_tables`,
`BOOT_TABLE_POOL_SIZE`, and the stage-2 table carve, `stage2_table_bound`, `find_boot_table_carve`,
and its bootstrap, `carve_bootstrap_end`, `carve_frames_below`, `map_carve_rest`, `switch_to_carve`,
and `extend_carve_mapped`), and the drain of RAM into Memory caps (`drain_and_install_seed`,
`reserve_init_backing`, `coalesced_extent_count`, `init_info_descriptor_bound`,
`INIT_INFO_DESCRIPTOR_CAPACITY`, `populate_cspace`, `complete_extent_descriptors`, and
`INIT_INFO_MAX_PAGES`), the frame map table's DRAM-span sizing (`dram_bounds`, `DRAM_BOUNDS`,
`frame_map::init`, `chunk_slots`, and `CHUNK_ORDER`), the `CSpace` registry arena's RAM sizing
(`init_cspace_registry`, `chunks_for_ram`, and `REGISTRY_CHUNK_ORDER`), and the kernel-stack
guard-table reserve's RAM sizing (`reserve_frames`). The screen works as the boundary one does:

```sh
git diff --stat "$B" <head> -- core/kernel/src/mm/buddy.rs core/kernel/src/mm/init.rs
M='translate_memory_map|max_ram_address|direct_map_ceiling|compute_max_physical_address'
M="$M|init_kernel_page_tables|BOOT_TABLE_POOL_SIZE|stage2_table_bound|find_boot_table_carve"
M="$M|carve_bootstrap_end|carve_frames_below|map_carve_rest|switch_to_carve|extend_carve_mapped"
M="$M|drain_and_install_seed|reserve_init_backing|coalesced_extent_count"
M="$M|init_info_descriptor_bound|complete_extent_descriptors"
M="$M|INIT_INFO_DESCRIPTOR_CAPACITY|populate_cspace|INIT_INFO_MAX_PAGES"
M="$M|dram_bounds|DRAM_BOUNDS|frame_map::init|chunk_slots|CHUNK_ORDER"
M="$M|init_cspace_registry|chunks_for_ram|REGISTRY_CHUNK_ORDER|reserve_frames"
git diff -W "$B" <head> -- . ':(exclude)*.md' | grep -E "^\+\+\+ |\b($M)\b"

# Memory variation (either arch; boots the current sysroot, so a debug-profile build):
cargo xtask run --arch <arch> --cpus 4 --mem 1024 --runs 1 --timeout 300
```

**Device surfaces.** The device cells, the boots of the system's devices that the canonical cells do
not make, are owed when, and only when, the PR's own diff makes a non-inert change to a device
surface that owes them. They are the storage cells of Disk variations below, each on each
architecture (4kn, the 4Kn disk; second-disk, the data partition on a second disk; shared-line, that
disk on the first disk's interrupt line; and oversize-block, the refused 8192-byte second disk),
no-iommu, the no-IOMMU variant of Release host runs below, framebuffer, the boot of Framebuffer cell
below, debug-port, the boot of Debug-port cell below, and hotplug, the boots of Hotplug cell below,
each on each architecture, and cet, the boot pair of CET cell below, and tpm, the boot pair of TPM
cell below, on x86_64 alone. A driver's
device surface is that driver's code, with the harness check that drives that driver alone where its
row names one; the storage-wide surface is the code every storage cell runs beside its drivers; and
the shared surface is what every driver shares, the launchers' attachment of the IOMMU in front of
every device included. Each surface is the files and directories its row lists, as a whole, and, in
any other file, a changed line that names one of its listed items as a whole identifier or lies
within one's definition; an item the row lists by its definition alone is on a surface only by a
changed line within that definition. In a file outside a
surface's files and directories, a changed line that names a listed type only in an import or
re-export, or in a signature or type annotation, is not on that surface by that name; it stays on
one when it names another listed item or lies within a listed item's definition. A line that reads
or writes one of the type's fields, calls one of its methods, or constructs or matches its value
names it in another use and stays on the surface. The exemption reaches no listed function
or constant: each stays on a surface as the sentences above define. The listed
types are `InterruptObject`, `Iommu`, `SecondDisk`, `DiskLine`, `BlockSize`, `FramebufferInfo`,
`InitFramebufferInfo`, `QemuDisplay`, `HotplugControl`, `BootEntropy`, `Tpm`, and
`TpmInterface`. A PR owes
the cells of every surface a non-inert line of its own diff is on.

| Surface | Files, directories, and items | Cells it owes |
|---|---|---|
| Shared: devmgr, the VirtIO core, the IRQ delivery path, and the devmgr protocol | `services/devmgr/`, `services/drivers/virtio/core/`, `core/kernel/src/irq.rs`, `core/kernel/src/arch/x86_64/ioapic.rs`, `core/kernel/src/arch/riscv64/aia.rs`, `core/kernel/src/arch/riscv64/aia_encoding.rs`, `core/kernel/src/arch/x86_64/msi.rs`, and `core/kernel/src/arch/x86_64/remap.rs`; the IRQ syscalls (`sys_irq_register`, `sys_irq_ack`, `sys_irq_split`, `sys_irq_msg_alloc`, `sys_irq_route`, and `sys_irq_remap`) and the kernel's Interrupt object (`InterruptObject`); the device-interrupt routing and entry (`route_device_irq`, `unroute_device_irq`, `irq_line_count`, `dispatch_device_irq`, the message-signaled targets' slots (`alloc_message_target`, `free_message_target`, and the slot entry a delivery reads, `slot_entry`), and, on x86_64, `irq_dispatch`, `common_irq_trampoline`, `device_irq_stubs`, `ioapics_into`, `select_ioapics`, and the allocation of the per-CPU device-vector rows the routes and targets take (`init_vector_storage`)); the interrupt-remapping switch and the entries it needs (`set_remap`, `remap_entry`, and `remap_handles`); the interrupt controller's acknowledge, mask, and unmask (by definition alone: `acknowledge`, `mask`, and `unmask` in `core/kernel/src/arch/*/interrupts.rs`); the riscv64 external-interrupt dispatch and claim (`dispatch_external`), the allocation of the IMSIC identity rows the routes and targets take (`init_eid_storage`), and the interrupt id range `SYS_IRQ_REGISTER` admits (`MIN_IRQ_ID` and `MAX_IRQ_ID`); and the devmgr protocol modules, as files (`shared/ipc/src/devmgr_labels.rs`, `shared/ipc/src/devmgr_errors.rs`, `shared/ipc/src/devmgr_dma_labels.rs`, `shared/ipc/src/devmgr_dma_errors.rs`, and `shared/ipc/src/device_info_kind.rs`); and the launchers' IOMMU attachment (`Iommu`, `virtio_property`, `RISCV_IOMMU_DEVICE`, `X86_IOMMU_DEVICE`, and `X86_MACHINE_SPLIT_IRQCHIP`) | every device cell |
| Storage-wide: vfsd, the storage protocol, and xtask's disk tooling | `services/vfsd/` (its GPT crate, `services/vfsd/gpt/`, included), the storage statement's crate `shared/storage-statement/`, `xtask/src/disk.rs`, its GPT writer `xtask/src/gpt.rs`, its FAT writer `xtask/src/fat.rs`, and `xtask/src/commands/mkdisk.rs`; the protocol modules between vfsd, the filesystem drivers, and the block drivers, as files (`shared/ipc/src/vfsd_labels.rs`, `shared/ipc/src/vfsd_errors.rs`, `shared/ipc/src/fs_labels.rs`, `shared/ipc/src/fs_errors.rs`, `shared/ipc/src/blk_labels.rs`, and `shared/ipc/src/blk_errors.rs`); and the launchers' disk devices and options (`blk_device`, `check_block_size`, `SecondDisk`, `disk_block_size`, `second_disk` and the `second_disk_*` options, `second_src`, `second_dst`, `second_line`, `DiskLine`, `SecondSlot`, `FIRST_DISK_SLOT`, `SECOND_DISK_SLOT`, `SHARED_LINE_FIRST_DISK_SLOT`, `MOVED_DISK_SLOT`, `first_disk_slot`, `SECOND_DISK_LOCATION`, `BlockSize`, and `split_data`) | every storage cell |
| virtio-blk | `services/drivers/virtio/blk/` | every storage cell, and no-iommu |
| fatfs | `services/fs/fat/` | 4kn |
| virtio-input | `services/drivers/virtio/input/` | no-iommu |
| virtio-rng and the `hwrng` class | `services/drivers/virtio/rng/`, its class protocol crate (`shared/hwrng-protocol/`), and svctest's hwrng checks, which drive it (by definition alone: `hwrng_read_phase`, `hwrng_restart_phase`, `hwrng_read`, and `hwrng_denied`) | no-iommu |
| virtio-console, the debug port, and the GDB stub | `services/drivers/virtio/console/`, the fixture and the host test that drive it (`services/fixtures/debug-echo/` and `xtask/src/commands/test/debug_port/echo.rs`), the protocol crate both ends of that test frame with (`shared/gdb-rsp/`), and the launchers' debug-port attachment (`debug_port_args` and `DEBUG_PORT_CHARDEV`); the GDB stub, its target, and the host test that drives them (`services/gdbstub/`, `xtask/src/debug_stub.rs`, and `xtask/src/commands/test/debug_port/gdb.rs`; by definition alone: the `debugger` fixture's `gdb_target`, `gdb_target_tick`, and `gdb_target_worker_step`); and procmgr's side of a debugger's attach that only that test drives (by definition alone: `handle_list_processes`, `handle_detach_process`, `restore_crash_bindings`, `watch_debugger`, and `check_debuggers`) | debug-port |
| test-dma | `services/drivers/test-dma/`, its protocol module, a file (`shared/ipc/src/test_dma_labels.rs`), the launchers' `edu` attachment (`EDU_DEVICE`), and svctest's DMA confinement, MSI delivery, MSI forge, MSI churn and MSI release checks, which drive it (by definition alone: `dma_confinement_phase`, `msi_delivery_phase`, `msi_forge_phase`, `msi_churn_phase`, `msi_release_phase`, `iommu_restart_phase`, and `call_test_dma`) | no-iommu, and hotplug |
| PCI Express hotplug | the fixture and the host test that drive it (`services/fixtures/hotplug-check/` and `xtask/src/commands/test/hotplug.rs`), and the launchers' hotplug ports (`hotplug_port_args`, `HOTPLUG_PORT_DEVICE`, `HOTPLUG_PORT_ID`, `HOTPLUG_DISK_PORT_DEVICE`, `HOTPLUG_DISK_PORT_ID`, `X86_NATIVE_HOTPLUG_GLOBAL`, `HotplugControl`, `HotplugPort`, `PortDisk`, `PORT_DISK_ID`, `PORT_DISK_NODE`, `PORT_DISK_LOCATION`, `port_disk_properties`, `port_disk_block_size`, `boot_disk_behind_port`, and `EDU_DMA_MASK`) and QMP's `blockdev-add`, `device_add` and `device_del` (`blockdev_add_raw`, `blockdev_add_raw_message`, `device_add`, `device_add_message`, `Property`, `device_del`, `device_del_message`, `device_del_request`, and `device_deleted`); and acpid's side of the firmware's ACPI PCI hotplug, which only the hotplug cell's firmware boot drives: its hotplug module (`services/acpid/src/hotplug.rs`), whose `HotplugSlots`, `HotplugJob`, and `HotplugNote` the server and the host hold, and the slots start-up hands to the evaluation thread (`hotplug_slots`); the hotplug thread and the evaluation thread's handling of a hotplug `Notify` and of a hotplug job's end (`HotplugServer`, `start_hotplug`, `route_hotplug_notes`, `ask_hotplug`, `end_hotplug_job`, `run_hotplug_methods`, and `Work::Hotplug`); the host's keeping of a hotplug `Notify` (`take_hotplug_notes`, and by definition alone: `notify` in `services/acpid/src/platform.rs`); and the `ACPI_HOTPLUG` call (`acpi_hotplug`) | hotplug |
| framebuffer, and the GOP framebuffer's path to it | `services/drivers/framebuffer/`, `core/boot/src/framebuffer.rs`, and `core/kernel/src/framebuffer.rs`, and the glyph chain every framebuffer renderer resolves through, `shared/text/` and `shared/font/`; the bootloader's GOP query and boot console (`query_gop` and `init_framebuffer`), the boot-protocol and init-protocol framebuffer records (`FramebufferInfo` and `InitFramebufferInfo`), and the kernel's console rebase and direct-map placement of the framebuffer (`rebase_framebuffer` and `framebuffer_above`), whose present-framebuffer paths only a boot with a GOP takes; and the launchers' display attachment (`QemuDisplay` and `display_args`) | framebuffer |
| serial, the RTC drivers, the IOMMU drivers, and the other test-only drivers | `services/drivers/serial/`, `services/drivers/cmos/`, `services/drivers/goldfish-rtc/`, `services/drivers/iommu/`, and `services/drivers/test-fault/` | none: the canonical cells boot their devices (Driver coverage above), and the no-iommu cell runs no IOMMU driver |
| TPM 2.0, and the bootloader's seed of its registers | `services/drivers/tpm/`, its class protocol crate (`shared/hwrng-protocol/`), which the virtio-rng row lists too, the host test that drives it (`xtask/src/commands/test/tpm.rs`), and the launchers' TPM attachment (`Tpm`, `TpmInterface`, and `tpm_args`); and the bootloader's `TPM2` table seed, which only a boot with a TPM takes (`tpm2_register_window`, `tpm_register_window`, `TPM2_OFF_CONTROL_AREA`, `TPM2_OFF_START_METHOD`, `TPM2_MIN_LEN`, `TPM2_START_FIFO`, and `TPM2_START_CRB`) | tpm |
| The boot-entropy path of `virtio-rng-pci` | the bootloader's draw (`step5c_fetch_boot_entropy`, `BootEntropy`, and `parse_rng_seed`) | none: the canonical cells boot it (Driver coverage above) |
| The CPU's CET shadow stacks, the kernel's x86_64 shadow-stack path | `core/kernel/src/arch/x86_64/shadow_stack.rs`, the host test that drives it and its gdbstub client (`xtask/src/commands/test/cet.rs` and `xtask/src/qemu_gdb.rs`), and the launchers' pin of the guest CPU's `cet-ss` property (`X86ShadowStack` and `qemu_knows_cet_ss`); every use of the module (`shadow_stack`) and of the Thread slot's shadow-stack page (`shadow_page`, `shadow_offset`, and `set_shadow_stack_pages`); the per-CPU and boot shadow-stack pages (`shadow_on_boot_cpu`, `make_cpu_shadow_pages`, `idle_shadow_pages`, `cpu_shadow_pages`, and `idle_saved_state`); the direct-map encoding and its retry (`shadow_direct_map_page`, `new_shadow_stack_page`, and `kernel_write_fault_is_spurious`); the code that runs on the supervisor shadow stack at every entry from user mode, or decides whether shadow stacks are on (`seraph_enter_from_user`, `__x86_indirect_thunk_r11`, `rewrites_returns`, and `RETURN_REWRITING`); and the paths shadow stacks check or switch (by definition alone: the x86_64 `switch`, `syscall_entry`, and `page_fault_handler`, and `mm::stack_guard`'s `hole` and `close`) | cet |

The 4kn cell runs the virtio-blk and fatfs drivers at 4096-byte blocks; the second-disk,
shared-line, and oversize-block cells vary the disks virtio-blk serves, and none of them varies what
fatfs reads. The no-iommu cell boots devmgr, the test-dma driver, and svctest's DMA confinement and
MSI delivery, forge, churn, and release checks unconfined, and every VirtIO driver without
`VIRTIO_F_ACCESS_PLATFORM`, which the launchers have a device offer only with the IOMMU attached, so
the shared surface (the launchers' IOMMU attachment among it), virtio-blk, virtio-input, virtio-rng,
and test-dma owe it. The cet cell runs the kernel on the CPU's CET shadow stacks, which neither the
CI runners nor TCG offer, so the canonical cells boot every path the CET row lists only with shadow
stacks off; the shared surface owes it too, since the IRQ entry and exit run on the shadow stack
when it is on. A PR that adds a driver adds its row, with its directory and the cells that
exercise its device, and a PR that adds a cell names the surfaces that owe it. `cargo xtask
lint-docs` checks this list as it checks the two above, its directories (written with a trailing
`/`) included, and resolves its items in xtask's own sources too. The screen works as the boundary
one does: the first command lists the changed files on a surface as a whole, and the others print
every candidate, which the PR owes the surface's cells for when a non-inert changed line names the
item or lies within its definition (within it alone for an item listed by definition alone), read
in that file's hunk, unless the line names a listed type only in an import, a re-export, a
signature, or a type annotation, as the first paragraph of Device surfaces defines it.

```sh
git diff --stat "$B" <head> -- services/devmgr/ services/drivers/virtio/core/ \
    core/kernel/src/irq.rs core/kernel/src/arch/x86_64/ioapic.rs \
    core/kernel/src/arch/riscv64/aia.rs core/kernel/src/arch/riscv64/aia_encoding.rs \
    core/kernel/src/arch/x86_64/msi.rs core/kernel/src/arch/x86_64/remap.rs services/vfsd/ \
    shared/storage-statement/ xtask/src/disk.rs xtask/src/gpt.rs xtask/src/fat.rs \
    xtask/src/commands/mkdisk.rs \
    services/drivers/virtio/blk/ services/fs/fat/ \
    services/drivers/virtio/input/ services/drivers/virtio/rng/ shared/hwrng-protocol/ \
    services/drivers/test-dma/ services/drivers/framebuffer/ \
    services/drivers/virtio/console/ services/fixtures/debug-echo/ \
    xtask/src/commands/test/debug_port/echo.rs \
    services/fixtures/hotplug-check/ xtask/src/commands/test/hotplug.rs \
    services/acpid/src/hotplug.rs \
    shared/gdb-rsp/ services/gdbstub/ xtask/src/debug_stub.rs \
    xtask/src/commands/test/debug_port/gdb.rs \
    core/boot/src/framebuffer.rs core/kernel/src/framebuffer.rs shared/text/ shared/font/ \
    core/kernel/src/arch/x86_64/shadow_stack.rs xtask/src/commands/test/cet.rs \
    xtask/src/qemu_gdb.rs shared/ipc/src/devmgr_labels.rs shared/ipc/src/devmgr_errors.rs \
    shared/ipc/src/devmgr_dma_labels.rs shared/ipc/src/devmgr_dma_errors.rs \
    shared/ipc/src/device_info_kind.rs shared/ipc/src/vfsd_labels.rs shared/ipc/src/vfsd_errors.rs \
    shared/ipc/src/fs_labels.rs shared/ipc/src/fs_errors.rs shared/ipc/src/blk_labels.rs \
    shared/ipc/src/blk_errors.rs shared/ipc/src/test_dma_labels.rs services/drivers/tpm/ \
    xtask/src/commands/test/tpm.rs
D='sys_irq_(register|ack|split|msg_alloc|route|remap)|(un)?route_device_irq|irq_line_count'
D="$D|dispatch_device_irq|set_remap|remap_entry|remap_handles"
D="$D|irq_dispatch|common_irq_trampoline|device_irq_stubs|ioapics_into|select_ioapics"
D="$D|(alloc|free)_message_target|slot_entry|init_vector_storage"
D="$D|InterruptObject|dispatch_external|init_eid_storage|M(IN|AX)_IRQ_ID"
D="$D|Iommu|virtio_property|RISCV_IOMMU_DEVICE"
D="$D|X86_IOMMU_DEVICE|X86_MACHINE_SPLIT_IRQCHIP|EDU_DEVICE"
D="$D|dma_confinement_phase|msi_(delivery|forge|churn|release)_phase|call_test_dma"
D="$D|hwrng_re(ad|start)_phase|hwrng_read|hwrng_denied"
D="$D|QemuDisplay|display_args|query_gop|init_framebuffer|(Init)?FramebufferInfo"
D="$D|rebase_framebuffer|framebuffer_above|debug_port_args|DEBUG_PORT_CHARDEV"
D="$D|hotplug_port_args|HOTPLUG_(DISK_)?PORT_(DEVICE|ID)|X86_NATIVE_HOTPLUG_GLOBAL|HotplugControl"
D="$D|HotplugPort|PortDisk|PORT_DISK_(ID|NODE|LOCATION)|port_disk_(properties|block_size)"
D="$D|boot_disk_behind_port|Property|blockdev_add_raw(_message)?"
D="$D|EDU_DMA_MASK|device_add(_message)?|device_del(eted|_message|_request)?"
D="$D|Hotplug(Slots|Job|Note|Server)|hotplug_slots|start_hotplug|route_hotplug_notes"
D="$D|ask_hotplug|end_hotplug_job|run_hotplug_methods|Work::Hotplug|take_hotplug_notes"
D="$D|acpi_hotplug"
D="$D|gdb_target(_tick|_worker_step)?|handle_list_processes|handle_detach_process"
D="$D|restore_crash_bindings|watch_debugger|check_debuggers"
D="$D|blk_device|check_block_size|SecondDisk|disk_block_size|BlockSize|split_data"
D="$D|second_disk(_[a-z_]+)?|second_(src|dst|line)|DiskLine"
D="$D|(FIRST|SECOND|SHARED_LINE_FIRST|MOVED)_DISK_SLOT|first_disk_slot|SecondSlot"
D="$D|SECOND_DISK_LOCATION"
D="$D|shadow_stack|shadow_page|shadow_offset|set_shadow_stack_pages|shadow_on_boot_cpu"
D="$D|make_cpu_shadow_pages|(idle|cpu)_shadow_pages|idle_saved_state|shadow_direct_map_page"
D="$D|new_shadow_stack_page|kernel_write_fault_is_spurious"
D="$D|seraph_enter_from_user|__x86_indirect_thunk_r11|rewrites_returns|RETURN_REWRITING"
D="$D|Tpm|TpmInterface|tpm_args|tpm2?_register_window"
D="$D|TPM2_(OFF_CONTROL_AREA|OFF_START_METHOD|MIN_LEN|START_FIFO|START_CRB)"
git diff -W "$B" <head> -- . ':(exclude)*.md' | grep -E "^\+\+\+ |\b($D)\b"
git diff -W "$B" <head> -- 'core/kernel/src/arch/*/interrupts.rs' |
    grep -E "^\+\+\+ |\b(acknowledge|mask|unmask)\b"
git diff -W "$B" <head> -- core/kernel/src/arch/x86_64/ core/kernel/src/mm/stack_guard.rs |
    grep -E "^\+\+\+ |\b(switch|syscall_entry|page_fault_handler|hole|close)\b"
git diff -W "$B" <head> -- services/acpid/src/platform.rs | grep -E "^\+\+\+ |\bnotify\b"
```

**Repeat count.** Every owed run, local or release, runs once (`--runs 1`); nothing raises the
count. A PR states a concurrency-fix purpose when its body states that its purpose is the fix of a
concurrency defect in the scheduling, wake, or cross-CPU signalling mechanisms. Such a PR, unless
its changes outside Markdown are all inert, owes the whole boundary set, whether or not its diff
changes the CPU-count surface: a defect in those mechanisms shows at the boundary CPU counts, which
CI does not boot. A few repeats add almost nothing to the chance of catching a race that fails
rarely; the burn-in tier is the repeated-run check. A concurrency fix elsewhere is not a
concurrency-fix purpose, and a change to those mechanisms' files without that stated purpose owes
nothing on that account.

**When the runs are owed.** Each local host run a PR owes MUST pass at one
head that covers the merge head. For every local and release host run, only a `PASS` outcome of
`run --runs` ([xtask/README.md](../xtask/README.md)) passes; a `QEMU-CRASH` run, a crash of the
host emulator, is run again and the re-run's outcome stands (`run --runs` exits non-zero on a set
with no `PASS`, whatever its `QEMU-CRASH` count, and tolerates a `QEMU-CRASH` only beside a
`PASS`); a run that ran beside another QEMU and
HANGs or fails a timing check is run again once with no other QEMU beside it (`--alone`), and the
re-run's outcome stands; `OK` and `ERR` count as failures. The
PR's own diff at a head is the diff from that head's merge base with the fetched `master` to the
head (after `git fetch origin`, `git diff $(git merge-base <head> origin/master) <head>`), so it
excludes what a merge or rebase from `master` brings in. A run's surface is the surface that owes
it: the CPU-count surface for the boundary set, the memory surface for the memory variation, the
device surfaces that owe a device cell for that cell, and, for the runs a concurrency-fix purpose
owes, every non-inert line of the PR's own diff. A run at head H covers a later head M when the
PR's own diff makes the same non-inert changes to that run's surface at H and at M. An update from
`master` that leaves those changes as they were therefore owes no run; one whose conflict
resolution alters them does. A fix round that alters them breaks the
coverage of the runs that surface owes, and those runs MUST be run again at a head after it. The PR
body MUST report each run it owes with its `--runs` count, its outcome, and the head it ran at, or
state that none is owed and why: that its changes outside Markdown are all inert, or that its
non-inert lines change none of the CPU-count, memory, and device surfaces and it states no
concurrency-fix purpose as Repeat count defines it. A PR whose lines are inert by Identical images
above quotes the command's verdict line and gives the head it ran at.

**Hangs at oversubscription.** A boundary run the PR does not owe, that is, one whose surface the
PR's own diff does not change, that HANGs (outlives its `--timeout` budget) or fails with a defect
an open Issue for that boundary already names is not the PR's defect: the preserved log is recorded
on the open Issue for that boundary, or on a new Issue when that boundary has none, and the run
does not block the PR. The PR body reports such a run as HANG or FAIL with a link to that record.
Any other HANG or failure of a run the PR does not owe (a memory-variation or device-cell HANG or
failure, or a boundary failure no open Issue for that boundary names), and any HANG or failure of a
run the PR owes, blocks the PR. Of a run that ran beside another QEMU and HANGs or fails a timing
check, the outcome judged is its re-run's alone (When the runs are owed). A flagged row of the
timing report is neither a HANG nor a failure.

**Disk variations.** Four svctest boots, on each architecture, vary the disk: a 4Kn disk (`mkdisk
--block-size 4096`), booted from a 4096-byte-block ESP with its root and data partitions at
4096-byte blocks; the data and swap partitions on a second disk, which the storage statement the
pack stages names (`mkdisk --split-data`, booted with `--second-disk disk-data.img`), so `/data`
lives only there; the same two disks on one `INTx` line (`--second-disk-shared-line`, which moves
the first disk onto the second's line and launches both with no MSI-X), so the svctest phases that
read `/data` pass only when devmgr serves both virtio-blk devices on one line (a lost interrupt
costs a disk request up to its interrupt-service thread's timed read, `ISR_POLL_MS`, not the boot,
so the boot's time, not its outcome, shows whether both drivers acknowledge every delivery); and a
second disk at 8192-byte blocks (`--second-disk-block-size 8192`), above virtio-blk's
`MAX_BLOCK_SIZE` (4096), which the boot goes on without. The storage and device documents own what
each boot exercises ([storage.md](storage.md) § GPT Role-GUID Discovery,
[device-management.md](device-management.md) § Relationship to Other Services and § Interrupt
Delivery), and [xtask/README.md](../xtask/README.md#cargo-xtask-run) gives the options. svctest is
staged as the canonical cells stage it, and its pass marker passes each boot. Each budget, 900 s, is
the larger of three times the slowest of these boots on the reference host (the riscv64 8192-byte
boot, 296 s) and that boot plus 100 s, rounded up to a minute, the rule the boundary budgets above
follow; a change to these boots' times re-derives it. Each boot is a storage cell (Device surfaces
above): in the commands below, 4kn is the first `run --runs` boot, second-disk the second,
shared-line the third, and oversize-block the fourth, each after the `mkdisk` before it; a PR that
owes some of the cells runs those boots, and the release host runs run all four.

```sh
# Disk variations, per architecture (clean between architectures):
cargo xtask build --arch <arch>
cargo xtask mkdisk --arch <arch> --repack-only --svctest ci --block-size 4096
cargo xtask run --arch <arch> --runs 1 --timeout 900 \
    --test-devices
cargo xtask mkdisk --arch <arch> --repack-only --split-data
cargo xtask run --arch <arch> --runs 1 --timeout 900 \
    --second-disk disk-data.img --test-devices
cargo xtask run --arch <arch> --runs 1 --timeout 900 \
    --second-disk disk-data.img --second-disk-shared-line --test-devices
cargo xtask mkdisk --arch <arch> --repack-only
cp disk.img target/xtask/second-disk.img
cargo xtask run --arch <arch> --runs 1 --timeout 900 \
    --second-disk target/xtask/second-disk.img --second-disk-block-size 8192 \
    --test-devices
```

**Framebuffer cell.** One svctest boot, on each architecture, keeps QEMU std VGA with no display
window (`run --display framebuffer`,
[xtask/README.md](../xtask/README.md#classified-boots---runs)), so the bootloader hands the
kernel the adapter's GOP framebuffer, devmgr spawns the framebuffer driver, and svctest's drivers
and `logd_sinks` phases run their framebuffer cases
([services/svctest/README.md](../services/svctest/README.md)) instead of logging
`framebuffer case skipped`. The boot passes on svctest's pass marker with no
such line: its `--fail-also 'framebuffer case skipped'` makes a boot that logs the skip a `FAIL`.
svctest is staged as `build-test.yml` stages it, on a debug-profile sysroot, as the commands
below spell out. Its budget, 960 s, is the larger of three times the slower of the two boots on
the reference host (the riscv64 boot, 301 s) and that boot plus 100 s, rounded up to a minute, the
rule the disk variations' budget follows; a change to these boots' times re-derives it. The boot
is the framebuffer device cell (Device surfaces above).

```sh
# Framebuffer cell, per architecture (clean between architectures):
cargo xtask build --arch <arch>
cargo xtask mkdisk --arch <arch> --repack-only --svctest ci
cargo xtask run --arch <arch> --runs 1 --timeout 960 \
    --display framebuffer --test-devices --fail-also 'framebuffer case skipped'
```

**Debug-port cell.** Two boots, on each architecture, each of which attaches the debug port's
`virtio-console` device, so devmgr binds it and the virtio-console driver runs: the `debug-port`
case's first boot (Debug port (`debug-port` case) above), in which the `debug-echo` fixture answers
the host over the port, and its second (GDB stub (`debug-port` case) above), in which the GDB stub
serves a host GDB session against the `gdb-target` process. The case runs both boots, the second
whatever the first's outcome, and the cell passes when both host checks pass; the case stages and
unstages its own recipes on the current sysroot, a debug-profile build. The first boot is bounded to
the fixture's ready line by five minutes and each answer by twenty seconds; the second is bounded to
the stub's ready line by five minutes, the GDB session by three, and the stub's detach line by 30 s
after it. Neither has a boot budget. The two boots are the debug-port device cell (Device surfaces
above).

```sh
# Debug-port cell, per architecture (clean between architectures):
cargo xtask build --arch <arch>
cargo xtask test debug-port --arch <arch>
```

**Hotplug cell.** The boots of `cargo xtask test hotplug` (PCI Express hotplug (`hotplug` case)
above) on each architecture, four on x86_64 and three on riscv64, at 4 vCPUs. In the device boots,
two on x86_64 (the firmware's ACPI PCI hotplug, then native control) and one on riscv64, devmgr
takes two empty root ports' events, binds the `test-dma` fixture to the `edu` device the host
hot-adds behind one, withdraws it when the host removes the device, binds it again when the host
adds it again, and binds the drivers directory's virtio-blk to the disk the host then hot-adds
behind the other, with no MSI-X vectors, on its wired interrupt line. In the two storage boots, vfsd
tears down the mount of a disk removed behind a port and mounts it again when it is added again,
gives the data role to that disk back at its location and not to a copy of it added at another,
and ends at the loss of its root filesystem's driver and of the boot disk. The command stages and
unstages its own files on the current sysroot, a debug-profile build. It bounds each boot to its
markers by five minutes, the fixture's probes and the disk's bind by three minutes after each
hot-add, and the removal by one minute from `device_del`; it has no boot budget. The boots are the
hotplug device cell (Device surfaces above).

```sh
# Hotplug cell, per architecture (clean between architectures):
cargo xtask build --arch <arch>
cargo xtask test hotplug --arch <arch>
```

**CET cell.** One boot pair on x86_64, `cargo xtask test cet` (CET shadow stacks (`cet` case)
above), whose first boot runs ktest with the kernel on CET shadow stacks and whose second checks
that a corrupted kernel return address raises `#CP`, on a sysroot holding the composed ktest
bundle, a debug-profile build, at 4 vCPUs. It runs only under KVM on a host whose CPU reports CET
shadow stacks and enhanced or Automatic IBRS: on any other host the command fails, naming what is
missing, and never passes, so a PR that owes the cell runs it on such a host. On a host that is
itself a guest, a run that ends in the host's loss of the guest's CET state is inconclusive and run
again, up to four runs of each boot, and the cell passes only on runs without it (CET shadow stacks
(`cet` case) above). Each boot is bounded by five minutes and each gdbstub answer by 30 s; it has no
boot budget. The pair is the cet device cell (Device surfaces above).

```sh
# CET cell, x86_64 only:
cargo xtask build --arch x86_64
cargo xtask mkdisk --harness ktest
cargo xtask test cet
```

**TPM cell.** One boot pair on x86_64, `cargo xtask test tpm` (TPM (`tpm` case) above), at 4
vCPUs, on the default boot set of a debug-profile sysroot, each boot backed by `swtpm`: one with
`tpm-tis` and one with `tpm-crb`. The command fails before the boots when `swtpm` is not
installed, naming the package. Each boot is bounded by three minutes; it has no boot
budget. The pair is the tpm device cell (Device surfaces above).

```sh
# TPM cell, x86_64 only:
cargo xtask build --arch x86_64
cargo xtask mkdisk
cargo xtask test tpm
```

**Release host runs.** Before each tag ([conventions.md](conventions.md#release-production) §
Release Production, step 4), these MUST be run on the commit to be tagged, or on an earlier commit
that contains the version bump when the change from it to the commit to be tagged is documentation
or comments only as this section defines that: the whole boundary set (riscv64 16 and 128 harts,
x86_64 16 and 128 vCPUs) once each (`--runs 1`) in the debug profile and once each in the release
profile (`cargo xtask build --release`, then the same `run` command, per the boundary commands
above), and the memory variation, the large-memory cell, and every device cell (the disk
variations, the no-IOMMU variant, the framebuffer cell, the debug-port cell, the hotplug cell, the
CET cell, and the TPM cell) once each, and every bounded proof (`cargo xtask kani` with no
option, [Bounded
verification](#bounded-verification)), and the fuzz campaign (§ Fuzzing): a manual dispatch of
`fuzz.yml` on `master` while the commit to be tagged is its head (`gh workflow run fuzz.yml --ref
master`), at the default time per target, whose run's head commit is that commit and whose
conclusion is `success`, the report giving the run's URL as its command, `--runs 1`, and `PASS` as
its outcome when the conclusion is `success`; so every tag boots at each boundary CPU count in both
profiles (CI boots release builds only at 4 CPUs), from a 4Kn disk, from two disks, with no IOMMU,
with a framebuffer, with a debug port, with a hot-added device, on CET shadow stacks, with a TPM,
and with 8 GiB of RAM under svctest, carries every proof a pull request's selection may have left
unverified and a campaign of every
fuzz target, and runs the timing report on the boundary logs, which is reported and blocks nothing.
A tag's repeated-run check is the burn-in tier, which the tag push starts. The no-IOMMU variant, the
no-iommu device cell, boots svctest once on each architecture with the machine's IOMMU detached, so
devmgr's unconfined path still serves every driver (svctest staged as `build-test.yml` stages it, on
a debug-profile sysroot). Its budget, 840 s, is the larger of three times its riscv64 boot on the
reference host (278 s) and that boot plus 100 s, rounded up to a minute, the rule the disk
variations' budget follows; a change to that boot's time re-derives it. A run whose outcome is not
a pass, as When the runs are owed classifies outcomes, blocks the tag, MUST be filed as an Issue,
and is bisected over the release's PRs.

```sh
# No-IOMMU variant, each architecture (svctest staged, debug profile):
cargo xtask run --arch <arch> --iommu absent --runs 1 --timeout 840 \
    --test-devices
```

**Large-memory cell.** One svctest boot, on each architecture, at 4 CPUs and 8192 MiB, staged as the
canonical svctest cell stages it (`mkdisk --svctest ci`, its fixtures, crashd's test recipe and
oomd's, with the test devices) on a debug-profile sysroot; the release host runs boot it once each,
and no pull request owes it. svctest's phases size their work by the guest's RAM against margins
that stay fixed, so a cost that grows with RAM overtakes such a margin only above some RAM size, and
only a boot above that size finds the defect; the memory variation's 1024 MiB can lie below that
size. No changed line identifies a sizing of that kind, so no surface could owe the cell to a pull
request without a judgement call; the release host runs boot it whatever the release's pull requests
touched, as they boot the boundary set. At 8192 MiB every byte count sized by RAM is past 2^32 as
well, and real hardware has that much RAM. Its budget, 11340 s, is the larger of three times its
riscv64 boot on the reference host (3777 s) and that boot plus 100 s, rounded up to a minute, the
rule the disk variations' budget follows; a change to that boot's time re-derives it. The x86_64
boot, under KVM, takes 690 s on the reference host.

```sh
# Large-memory cell, per architecture (clean between architectures):
cargo xtask build --arch <arch>
cargo xtask mkdisk --arch <arch> --repack-only --svctest ci
cargo xtask run --arch <arch> --cpus 4 --mem 8192 --runs 1 --timeout 11340 \
    --test-devices
```

**Documentation-only and comment-only changes.** A diff that, Markdown
aside, alters only comment lines in source files cannot change program
behaviour other than the source positions that `#[track_caller]`, `line!()`,
and `column!()` record and assertion messages carry, which the CI gate's
boots cover, so none of the local host runs in this section are required for
it, whatever paths it touches. Source text a build embeds verbatim
(`include_str!`, `include_bytes!`, `global_asm!` inputs) is build input, not
comment or Markdown. The CI gate applies unchanged, and the
[pre-merge review](conventions.md#branch-and-pr-workflow) applies as
conventions.md § Branch and PR Workflow defines it, its auditor-only run
after a documentation- or comment-only fix round included; the PR body MUST
carry what
[conventions.md](conventions.md#pr-body-checklist-discipline) § PR-body checklist
discipline requires (the validated head, that the delta is documentation or
comments only, and the local host runs the PR as a whole owes, each with its
count, its outcome, and its head, or that none is owed and why), and the pre-merge review's
audit MUST check that against the diff.

**Known boundaries**, established empirically (QEMU 11.0.1; update this
list as the tracking Issues move):

- x86_64 > 256 CPUs ([#376](https://github.com/kottlerg/seraph/issues/376),
  fixed): the per-CPU boot slabs (`AP_IST_STACKS`, `AP_TSS`) exceeded the
  buddy allocator's old `MAX_ORDER = 10` single-allocation cap (4 MiB) at
  257+ CPUs, failing Phase 4 regardless of guest memory size. A per-CPU slab
  may now span several buddy blocks (`alloc_zeroed_slab` through
  `BuddyAllocator::alloc_contiguous`), so no block size caps the CPU count.
  No local run boots past 128 vCPUs; the residual entry below states what
  covers the widths past it.
- riscv64 ≥ 128 harts ([#377](https://github.com/kottlerg/seraph/issues/377),
  fixed): boot died in UEFI (`ConvertPages: Incompatible memory types`) while
  loading the kernel ELF, because the bootloader requested the image at a fixed
  `p_paddr` (`0x80200000`) that hart-scaled firmware allocations had already
  claimed — independent of guest memory size. The kernel image is now placed as
  one contiguous span allocated anywhere (`AllocateAnyPages`; on x86_64, anywhere
  below 4 GiB with `AllocateMaxAddress`), so loading tolerates any firmware layout;
  `validate_kernel_layout` enforces the
  [relocation invariants](../core/boot/docs/elf-loading.md#elf-validation) (single
  offset, alignment, non-overlap, entry-in-image) at load time. 128 harts now
  boots clean at 8× hart oversubscription on a 16-core host (the boundary run above).
  The residual ceiling is upstream and pre-bootloader: at 192, 256, and 512
  harts under TCG the edk2 firmware emits
  no serial output at all (192: nothing in 60 min; 256/512: nothing in 20/30
  min) — an MP-init crawl that runs before Seraph's bootloader and cannot be
  addressed in-tree. High-hart cross-architecture parity is therefore
  theoretical, with real testing on hold pending faster firmware, KVM-capable
  RISC-V emulation, or real hardware.
- Both arches, widths past 128 CPUs (residual): the boundary set stops at 128,
  so no local run exercises x2APIC destinations above APIC id 255, threshold
  effects that begin past 128 CPUs (a third CPU-set word, a bound that grows
  with the width), or a boot that allocates the per-CPU slabs past 128. What
  covers widths up to `MAX_CPUS` instead: the host tests of `AtomicCpuMask` at
  1, 63, 64, 65, 512, 768 and `MAX_CPUS` CPUs (`core/kernel/src/cpu_mask.rs`);
  the host test that an address space's wrapper page holds its active-CPU set
  at `MAX_CPUS` (`core/kernel/src/mm/address_space.rs`); the host tests of
  `BuddyAllocator::alloc_contiguous` (`core/kernel/src/mm/buddy.rs`: a run
  past one block, a run that cannot be found, and requests of one block or
  less) and of the byte-to-page rounding `alloc_zeroed_slab` applies
  (`sched::slab_pages`); the sizing of every per-CPU slab, whose byte count
  each initialiser takes from its `sched::PerCpuSlab` descriptor, checked at
  the widths of `sched::SLAB_CHECK_WIDTHS` (the word edges, 512, 768 and
  `MAX_CPUS`; a slab sized at the ceiling is sized at every smaller count) for
  a count that does not overflow and `slab_pages` that cover it: by a
  compile-time assert beside each
  descriptor of a fixed per-CPU count, against the target's own layout on both
  architectures, and for the tag-state and TLB acknowledgement-set slabs,
  whose per-CPU counts `tag_count` and `cpu_mask::mask_words` set at boot, by
  host tests (`sched::slab_tests`); and the 128-CPU boots
  for two full words.
- Both arches, a partial second CPU-set word (residual): no local run boots
  a count past one 64-bit word that does not fill the next (65 to 127 CPUs).
  The host tests of `AtomicCpuMask` cover those mask paths instead, at 63, 64
  and 65 CPUs among their widths:
  `every_cpu_of_a_boot_sets_tests_takes_and_clears_its_own_bit` and
  `filling_from_every_cpu_below_a_count_excepts_one`, in
  `core/kernel/src/cpu_mask.rs`.
- Both arches, high CPU counts ([#375](https://github.com/kottlerg/seraph/issues/375),
  fixed): the intermittent silent wedge around the `thread::load_balancer_*`
  and `stress::double_enqueue_storm` tests was a load-balancer ticket-lock
  convoy — every idle CPU queuing interrupts-off on one victim's run-queue
  lock every tick; the pull path now try-locks and backs off. A new silent
  high-CPU HANG should instead produce a `=== WATCHDOG` dump (owed-wake /
  heartbeat detectors) naming the wedged state; file it with the preserved
  log rather than attributing it to #375.
- Both arches, guest RAM ≥ ~4 GiB ([#383](https://github.com/kottlerg/seraph/issues/383),
  fixed): boot died at Phase 9 (`FATAL: Phase 9: InitInfo region too large`)
  because the kernel minted one userspace Memory cap — and one `CapDescriptor`
  — per drained buddy block, and the buddy's largest block is order-11 (8 MiB),
  so the descriptor array grew ~linearly with RAM (≈64 descriptors at 512 MiB,
  ≈512 at 4 GiB) and overflowed the `INIT_INFO_MAX_PAGES = 4` (16 KiB) Phase-9
  InitInfo region — independent of where the kernel image is placed.
  `drain_and_install_seed` now coalesces physically-adjacent drained blocks
  into the fewest contiguous Memory caps before minting (see
  [process-lifecycle.md § Kernel → init](process-lifecycle.md#kernel--init)), so the descriptor
  count tracks memory-map fragmentation (a small fixed number of usable extents
  plus reservation holes), not total RAM. The capacity check now runs at Phase 7,
  where the drain and `push_descriptor` log the count against the reserved
  region's descriptor capacity before fatal-ing, so any residual overflow on a
  pathologically fragmented map is diagnosable rather than bare. Verified booting
  clean to the ktest pass marker on both arches at `--mem 4096`.

---

## Fuzzing

The parsers of hostile input are fuzzed on the host by an in-tree coverage-guided engine,
`xtask/fuzz/engine`, which uses no registry crate and no external tool
([coding-standards.md](coding-standards.md#dependencies) § Dependencies). `cargo xtask fuzz`
([xtask/README.md](../xtask/README.md#cargo-xtask-fuzz)) builds the fuzz targets of
`xtask/fuzz/targets` with the pinned rustc's SanitizerCoverage instrumentation (an 8-bit counter
per edge and compare tracing) and, where the host target supports it, AddressSanitizer, in the
`fuzz` profile, which keeps panics unwinding, debug assertions, and overflow checks
([build-system.md](build-system.md#build-profiles) § Build Profiles).

**Layout.** A fuzzed parser has three parts:

- Its property: `pub fn <parser>_holds(input: &[u8])` in the parser crate's `property` module,
  compiled under `#[cfg(any(test, kani, fuzzing))]`, so no image carries it. It panics when the
  parser breaks its contract on the input, and asserts that contract, not only that the parser
  returns:
  for the GPT parser (`services/vfsd/gpt`), that an accepted header's CRC32 and `MyLBA` match
  and its entry array lies outside the usable range, that the partition walk reads exactly the
  array's blocks inside the disk and judges the array's CRC32 rightly, that a disk's partitions
  come from the primary GPT or, when it fails, the backup, and that each decoded entry re-encodes
  to its own bytes.
- Its checked-in inputs, under `<crate>/fuzz/<target>/`: `seeds/`, inputs that reach the parser's
  paths, and `regressions/`, each failing input a fuzz run found, minimized, added by the PR that
  fixes it. A `#[cfg(test)]` test of the crate runs the property on every one, so
  `cargo xtask test` replays them on each change, on the host and under riscv64 emulation.
- Its target: `xtask/fuzz/targets/src/bin/<target>.rs`, which names the property, the inputs'
  directory, and the longest input the engine makes, and one line for it in each of the two
  name-ordered lists of `xtask/fuzz/targets/Cargo.toml`, the binaries and the parser crates.

**The engine.** Each run is AFL-style: a queue of the inputs that reached a new edge or a new
hit-count bucket of one; havoc mutations and splices of the queued inputs; a dictionary of the
constants the target compares against; and input-to-state replacement, which writes one operand
of a comparison the parent input executed where the input holds the other. Every choice comes from
one generator seeded by `--seed`, and a supervising process runs the search with address-space
randomization off on a Linux host, since compare operands include addresses: a run of a fixed
execution count from a fixed seed, over the same checked-in inputs and working corpus, is
reproduced by the same command on the same host. A host that refuses to turn randomization off
(a container's default seccomp profile does) still runs the search, which then says that it is
not reproducible from its seed. The property runs under a panic catch; the
supervisor catches what no catch can: a signal, an AddressSanitizer report, an allocation over the
cap, and an input that runs over the time limit.

**Triage.** A failing input is minimized while it fails at the same location, and written with
its report under `target/xtask/fuzz/<target>/crashes/`: the panic message, its location, the
execution that found it, the seed, a symbolized backtrace, and the replay command
(`cargo xtask fuzz <target> --replay <file>`), which runs the property once on the input and
fails as the search did, on any host. The run exits non-zero.

**Cadence.**

| Tier | Where | When | Runs |
|---|---|---|---|
| Gating | CI, the `fuzz` job of `build-test.yml` | a change that can affect a crate it fuzzes, its engine, xtask or the workflows; skipped as not owed otherwise | `cargo xtask fuzz --self-test`, then every target for the default 200,000 executions from seed 0, from the checked-in inputs alone, each under a wall-clock cap of 20 minutes |
| Campaign | CI, `fuzz.yml` | a manual dispatch, one of them in the release host runs before each tag (§ Coverage tiers) | every target for 30 minutes, one job per target side by side, from a seed that changes each run, over the checked-in inputs and the target's working corpus of an earlier run when the Actions cache still holds one; failing inputs upload as an artifact |
| Local | developer host | at will | `cargo xtask fuzz <target>` with `--runs` or `--time` |

**Time.** The gating run's time is a stated budget. Each target's run of the default count is
capped at 20 minutes of wall-clock time (`DEFAULT_CAP_SECS`), about two and a half times the
slowest target's run in the gating job (about 8 minutes, of a job of about 17); a target past the
cap is stopped and fails the job, named as over the cap, and is a defect of the target or of its
property, made faster before it merges: a property whose checks grow faster than the input,
over inputs of up to the target's longest, is the usual cause. The job's `timeout-minutes` is the
backstop for the rest, and every fuzz job sets one. A campaign job's, 60 minutes, holds a
dispatch's time of up to 2700 seconds per target with the build and the minimization, and
`fuzz.yml` fails a dispatch of a longer time before any target runs.

The self-test runs the engine on planted defects in `xtask/fuzz/targets` (an eight-byte magic
compared as one integer, a length field whose add overflows, and a state reached only through
three nested records with no checksum) and fails unless each is found within its execution budget
from seed 0, twice, at the same execution with the same minimized input.

The campaign gates no merge: a red campaign run is a finding, recorded as
[conventions.md](conventions.md#recording-findings) § Recording findings says. The campaign the
release host runs dispatch on the commit to be tagged gates the tag (§ Coverage tiers, Release host
runs).

**Predating defects.** A failing input the gating job finds on a pull request whose own diff does
not introduce the defect (the same run fails at the merge base) is fixed first, in its own PR or
in the same one, as a red `master` is ([conventions.md](conventions.md#ci-gating) § CI Gating).

**Parser rule.** A parser of hostile input (bytes from a disk image, a device, the network, or
another process across an IPC boundary) MUST land with its property function, its seeds, its replay
test, and its fuzz target, as Layout above describes, and with the proof harnesses of its property
([Bounded verification](#bounded-verification), Parser proofs).

---

## Bounded verification

Kani, a bounded model checker for Rust, proves a property of pure, sequential code for every input
up to the bounds a proof harness states, where a host unit test checks the inputs it names. It
covers the kernel's pure, sequential logic and the parsers of input from outside a component's
trust boundary. A harness is a `#[kani::proof]` function in a `#[cfg(kani)] mod proofs`, written
to the rules of [coding-standards.md](coding-standards.md#proof-harnesses) § Proof Harnesses.

`cargo xtask kani` ([xtask/README.md](../xtask/README.md#cargo-xtask-kani)) runs every harness of
every crate that holds one, each crate built in its host test configuration, with the pinned Kani
release ([build-system.md](build-system.md#toolchain) § Toolchain). It fails on any failed,
undetermined or unwinding-incomplete check, on a Kani release other than the pinned one, and on a
harness that lies in no package. It finds the crates from their harnesses, so a crate's first
harness adds it to the run. It holds each process of the run to the address space CI's runner can
give a harness, so a harness that needs more fails, named as out of memory; it stops each
harness at a wall-clock time limit, so a harness that runs past it fails, named as over budget;
and it closes with every harness's verdict and verification time, then the ten slowest.

**Where the proofs run.** On a pull request, CI's `kani` job verifies only the crates the change can
affect (`cargo xtask kani --since` against the base the `select` job found, the newest commit before
the run's whose `master` run passed, or has not finished with no newer red or cancelled one;
[conventions.md](conventions.md#ci-gating)
§ CI Gating): a crate that holds a harness and whose own package, a workspace package in its
dependency closure (Markdown aside), or a file those read, the change touches, and every such crate
when the change touches an input of every proof (the workspace manifest and lock file, Cargo's
configuration, the toolchain pin, and the command's own source, which holds the Kani pin, the
arguments and the judge). A change to `build-test.yml`, whose steps run the job, that selects no
crate otherwise selects the crate with the fewest harnesses, so the job's steps run. That selection
gates the merge, and a pull request that affects no such
crate ends the job without installing Kani, with a notice on the run that it verified nothing. On a
push to `master` the job runs the same selection from the newest commit whose `master` run passed,
so a harness a red or cancelled `master` run left unproven stays owed until a run proves it. The
whole set runs in the `kani` job of `burnin.yml`, on each tag push and on a manual dispatch, and in
the release host runs (§ Coverage tiers), so a change the selection missed is found before a tag
([build-system.md](build-system.md#continuous-integration) § Continuous Integration).

**Local sizing.** A harness is sized on the development host before CI runs it. The author of a
change that adds a harness, or changes one's body, bounds or `kani::any` sizes, MUST run it there
with `cargo xtask kani --component <crate> --harness <name>` before the first push that carries
it, under the limit the command sets on every process of the run: 12 GiB of address space, the share
of the 16 GB of CI's `kani` runner ([GitHub's standard Linux runner for a public
repository](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)) that
leaves 4 GB to the runner's own processes, so a harness that fits under it locally fits on the
runner. A run that the limit ends (an allocation failure, or a process killed)
or that does not finish MUST be made to fit before the harness is pushed, by smaller bounds that
still cover the property or by the induction form of the parser proofs below. Beside the memory
limit, each harness has a time limit: the command stops a harness's CBMC after 10 minutes of
wall-clock time (`HARNESS_TIME_LIMIT_SECS`) and fails it as over budget. The limit is a backstop
set from the measured full run on CI's runner below, not a bound a harness is sized to: a harness
over it is a defect of the harness, made to fit the same way, by a narrower bound or a split into
harnesses that together cover the property. Every `kani` job sets a `timeout-minutes`, the
backstop for the rest. A failed,
undetermined or unwinding-incomplete check is not a sizing result: it is a defect in the code
or the harness, fixed as such, and MUST NOT be bounded away. The PR body's `## Validation`
section states, for each such harness, the verification time Kani reports, the peak resident
memory of the run (the maximum resident set size of its largest process, as GNU `time -v`
reports it), and the unwind bounds the harness carries. This run is owed whatever § Coverage
tiers owes, since a harness change is inert there.

**Measured time.** The whole set, 148 harnesses at `master` 3b95662c0, took 84 minutes in one
`kani` job on CI's runner (run 45719550314), the harnesses' own verification times summing to 82
minutes. Its slowest harness, devmgr-firmware's proof of the small AML resource descriptors, took
29 minutes as one CBMC problem and is four harnesses, one per descriptor. The next slowest took
235 s. The time limit of 10 minutes is about two and a half times that: room for a slower runner,
and a harness past it costs the run no more than the limit. The `timeout-minutes` of 120 on each
`kani` job holds the whole set with about 40 per cent to spare.

Kani verifies sequential code only: concurrency stays with the booted harnesses and the coverage
tiers above. It compiles inline assembly to a failing check, so a harness fails only if it reaches
one; its loops are bounded; and it does not detect every aliasing or provenance violation
([Kani's limitations](https://model-checking.github.io/kani/limitations.html),
[supported Rust features](https://model-checking.github.io/kani/rust-feature-support.html)).

**Parser proofs.** The property function of a parser of hostile input (§ Fuzzing, Layout) has a
third driver beside its replay test and its fuzz target: the `#[kani::proof]` harnesses in the
parser crate's `#[cfg(kani)] mod proofs`, which prove the property in one of two forms. A harness
runs the property, or its check of one structure the parser decodes (a header, an entry), on the
first `len` bytes of `kani::any::<[u8; N]>()`, `len` itself any value up to N, so the check holds
for every input of at most N bytes, not only for the inputs a search reached; its comment states N
and why inputs of that length cover the structure. Where a harness of the whole property cannot
be sized as Local sizing above says, the parser MUST write each loop over a structure of variable
length (the walk of an array, a search over its entries, a checksum over its bytes) as a step over
a small state, which two harnesses prove by induction: a base harness, that the loop starts in an
invariant the harness states, and a step harness, that one step from any state in the invariant
(`kani::any` under `kani::assume`) keeps it and does what the property asks of that step, with no
loop to unwind. Code other than the loops that drive the steps and the reads that feed them MUST NOT
lie outside the harnesses; the module's comment states how its harnesses compose into the property
and names those loops and reads, with the drivers that check them. Implemented for the parsers whose
crates hold a `property` module, each with its fuzz target in `xtask/fuzz/targets`; design
intent, not yet implemented, for every other parser of hostile input.

---

## Cross-harness conventions

These conventions apply to harnesses launched as svcmgr services (`svctest`,
`usertest`); `ktest`, the init replacement, has no recipe and powers off directly
via ACPI (x86_64) or SBI (riscv64) per `KtestConfig::DEFAULT.shutdown_policy`
(see [core/ktest/README.md § Shutdown](../core/ktest/README.md#shutdown)).

- **Completion behavior.** A harness MUST request `pwrmgr` shutdown when
  it finishes (pass or fail). This terminates the QEMU instance and lets
  CI move on. Harnesses launched as services obtain the shutdown
  capability via the seed-only `pwrmgr.shutdown` seed in their `.svc`
  recipe.
- **Restart policy.** A harness MUST set `restart = never` in its `.svc`
  recipe. Re-running on accidental exit corrupts CI semantics.
- **Critical class.** A harness MUST set `critical = no`. Harness death
  MUST NOT bring down the supervisor or trip the graceful-shutdown path.
- **Capability seeding.** A harness depends only on seeds declared in
  its `.svc` recipe and on public names it resolves through svcmgr's
  `QUERY_ENDPOINT`. A test that needs a seed the bootstrap rounds did not
  deliver, or a public name that did not resolve, MUST log the missing cap
  when it skips or fails, so failures attributable to missing capabilities
  are diagnosable.

---

## Troubleshooting

A failing boot is diagnosed with the tool that fits its class of defect:

| Defect class | Tool |
|---|---|
| Timing-sensitive race: a failure that comes and goes across boots, or moves with the CPU count or host load | Log instrumentation and repeat runs |
| Deterministic userspace fault | The crash report on the serial log, resolved with `cargo xtask symbolize --log` |
| Deterministic kernel crash; a failure before the serial console is up; a wedged guest; a question about raw machine state | QEMU's gdbstub |
| Per-process debugging of a running system | The GDB stub over the debug port |

**Races.** A debugger stops the CPUs it inspects and moves the timing a race depends on, so a
race is chased with log lines placed around the suspect window and with repeated boots, which turn
a rare failure into a rate: `cargo xtask run --runs N --parallel P --save-logs DIR`
([xtask/README.md](../xtask/README.md#classified-boots---runs)) keeps the log of every failing
run, and the CPU counts of [Coverage tiers](#coverage-tiers) are where SMP races show first.

**Failures only CI shows.** A defect whose effect depends on where the linker placed a static,
such as a stack overflow into a neighbouring object, reproduces only in a build with the same
layout. `cargo xtask build` builds without incremental compilation, as CI's jobs do
([docs/build-system.md](build-system.md#build-profiles) § Build Profiles), but a pull request's
CI run builds the PR's merge commit with `master` (`refs/pull/<N>/merge` at the SHA the run
names), not the PR head, so a local reproduction builds that commit. A local binary still differs
from CI's in the rust-src paths of its panic-location strings, which name the runner's toolchain
directory, so a static placed after those strings sits at an offset from CI's address.

**Userspace faults.** With crashd staged, the default, a fault that kills a process procmgr
created leaves a crash report: a marked block in the system log carrying the registers, the bytes
at the instruction pointer, the load bias, and a stack walk
([services/crashd/README.md](../services/crashd/README.md),
[services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md)). `cargo xtask
symbolize --log <file>` ([xtask/README.md](../xtask/README.md#cargo-xtask-symbolize)) prints every
block of a saved serial log with its instruction pointer and stack frames resolved to function,
file, and line against the symbols of the process's sysroot binary, which the symbols store keeps
under the binary's build id ([docs/build-system.md](build-system.md#symbols-store) § Symbols
Store), or to the nearest function symbol in a build without debug information, and
`run --runs` writes that report beside each log it keeps that holds a block. A process crashd
cannot cover (Crash reports above) leaves only the kernel's `USERSPACE FAULT` dump
([docs/fault-handling.md](fault-handling.md)), whose instruction pointer
(`rip=` on x86_64, `sepc=` on riscv64) is a runtime address in the process's image: with the load
bias from the creator's spawn line
([docs/userspace-memory-model.md](userspace-memory-model.md#image-placement) § Image Placement),
`cargo xtask symbolize --binary <binary> --bias <bias> <address>...` resolves it the same way.

**Kernel crashes, early failures, and wedged guests.** QEMU's gdbstub reads the machine whatever
state the guest is in, including before the serial console is up and after the kernel stops
answering. `cargo xtask run --gdb` starts the guest paused with the stub on `localhost:1234`;
`cargo xtask run --runs 1 --debug-listen --hold-on-hang` runs it unpaused and keeps a
hung guest alive for attaching
([xtask/README.md](../xtask/README.md#classified-boots---runs)). GDB runs in batch mode, so its
output lands in a file like any log. The kernel is static-PIE, so its symbols load at the KASLR
slide from the serial-only `kaslr: slide=` line, or at their link addresses in a boot whose disk
was authored with `cargo xtask mkdisk --knob nokaslr`; a userspace image's symbols load at its
bias, as [xtask/README.md](../xtask/README.md#cargo-xtask-run) describes under `--gdb`. Source lines
need the image built with debug information (`cargo xtask build --debug kernel`,
[docs/build-system.md](build-system.md#debuginfo-is-opt-in)). On riscv64 the GDB must be built for
that target ([docs/build-system.md](build-system.md#toolchain)).

```sh
# A wedged guest: boot until HANG, then, from another shell, read every CPU's
# state (SLIDE from the log's `kaslr: slide=` line; `bt 8` bounds each unwind,
# which otherwise runs on past a CPU's entry frame into stack words) and end
# the held guest:
cargo xtask run --arch riscv64 --runs 1 --timeout 300 \
    --debug-listen --hold-on-hang
gdb -batch -ex 'target remote :1234' \
    -ex "symbol-file -o $SLIDE sysroot/esp/EFI/seraph/kernel" \
    -ex 'thread apply all bt 8' -ex 'info registers' -ex kill

# A deterministic kernel crash: stop at the panic handler of a boot without
# KASLR, with source lines (a hardware breakpoint, since the kernel is not yet
# mapped when the guest starts paused, so a software one cannot be written):
cargo xtask build --debug kernel
cargo xtask mkdisk --knob nokaslr
cargo xtask run --gdb --display headless  # in one shell; waits paused
gdb -batch -ex 'target remote :1234' -ex 'hbreak kernel::panic' -ex continue \
    -ex bt -ex 'info registers' sysroot/esp/EFI/seraph/kernel
```

**A process of a running system.** The GDB stub
([services/gdbstub/README.md](../services/gdbstub/README.md)) debugs one process from a host GDB
while the rest of the system runs on: breakpoints, single-step, registers and memory of each of
its threads, then a detach that hands it back to the crash service. `cargo xtask run --debug-port
<PORT> --debug-target <NAME>` stages the stub for the boot, naming the process by its `argv[0]`
(for a service, the first word of its recipe's `argv`; for devmgr, vfsd and svcmgr, which init
creates, the service's name; for a driver devmgr binds, its bundle entry name or install path), and
prints the GDB command line, which loads the symbols store's file of the process binary's build id
(`symbols/<build-id>.elf`) for symbols; the stub reports the image's load bias (`qOffsets`), so
GDB relocates them itself
([xtask/README.md](../xtask/README.md#cargo-xtask-run)). A process that declared itself
undebuggable (the debug port's virtio-console driver and every debug-authority holder) refuses
the attach, and a process procmgr did not create (init,
memmgr, procmgr) is not listed.

```sh
# Debug the `gdb-target` fixture (staged by hand here; the `debug-port` case's GDB stub
# boot does the same):
cargo xtask build
cp sysroot/config/svcmgr/tests/gdb-target.svc sysroot/config/svcmgr/services/
cargo xtask mkdisk --repack-only
cargo xtask run --debug-port 4561 --debug-target gdb-target   # in one shell
# in another shell:
gdb -ex 'set architecture i386:x86-64' -ex 'set remotetimeout 30' \
    -ex 'target remote localhost:4561' \
    "symbols/$(awk '$1 == "/tests/fixtures/programs/debugger" {print $2}' symbols/manifest)"
```

---

## Historical naming

The identifier `usertest` formerly named the services-tier harness, which
lived at `base/usertest/`. The rename pass that landed under PR #119
relocated that harness to `services/svctest/`, freeing the `usertest`
name. As of this document, `usertest` is the programs-surface
orchestrator at `programs/usertest/`. References to `usertest` in commit
history before that rename refer to the prior services-tier harness.

See [conventions.md](conventions.md) for the original historical-naming
note in full.

---

## Summarized By

[README.md](../README.md), [Kernel Entropy Subsystem](../core/kernel/docs/entropy.md),
[core/ktest/README.md](../core/ktest/README.md), [Build System](build-system.md),
[Console Model](console-model.md), [Project Conventions](conventions.md),
[Threat Model](threat-model.md), [programs/hello/README.md](../programs/hello/README.md),
[programs/shell/README.md](../programs/shell/README.md),
[programs/terminal/README.md](../programs/terminal/README.md),
[programs/usertest/README.md](../programs/usertest/README.md),
[services/crashd/README.md](../services/crashd/README.md),
[services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md),
[services/fixtures/crashme/README.md](../services/fixtures/crashme/README.md),
[services/fixtures/debug-echo/README.md](../services/fixtures/debug-echo/README.md),
[services/fixtures/debugger/README.md](../services/fixtures/debugger/README.md),
[services/fixtures/fsbench/README.md](../services/fixtures/fsbench/README.md),
[services/fixtures/hotplug-check/README.md](../services/fixtures/hotplug-check/README.md),
[services/fixtures/program-modes/README.md](../services/fixtures/program-modes/README.md),
[services/fixtures/service-modes/README.md](../services/fixtures/service-modes/README.md),
[services/fixtures/stdiotest/README.md](../services/fixtures/stdiotest/README.md),
[services/gdbstub/README.md](../services/gdbstub/README.md),
[services/pwrmgr/README.md](../services/pwrmgr/README.md),
[services/svcmgr/README.md](../services/svcmgr/README.md),
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md),
[services/svctest/README.md](../services/svctest/README.md),
[services/ubench/README.md](../services/ubench/README.md),
[shared/aml/README.md](../shared/aml/README.md), [xtask/README.md](../xtask/README.md)
