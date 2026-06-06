# Testing

System-wide standard for the in-tree test harnesses, the per-program tester
protocol, the sysroot layout for test binaries, and the gating mechanism
that determines which harnesses run in a given boot.

---

## Harnesses

Three harnesses exercise three surfaces:

| Harness | Surface | Crate | Launch mechanism |
|---|---|---|---|
| `ktest` | Kernel | `core/ktest/` | Bootloader-loaded init replacement (`cargo xtask compose-bundle --harness ktest`) |
| `svctest` | Services | `services/svctest/` | `svcmgr` spawns from `/config/svcmgr/services/` recipe |
| `usertest` | Programs | `services/usertest/` | `svcmgr` spawns from `/config/svcmgr/services/` recipe; drives binaries under `programs/` through their real I/O surfaces. Also hosts the terminal interactive test (`cargo xtask test-terminal`), which injects keys over QMP through the live virtio-input driver and the autostarted terminal |

`ktest` and `svctest` are authoritative for their own surface; the harness
itself owns its phases. `usertest` is an orchestrator that runs per-program
tester binaries discovered under `/tests/programs/`.

---

## Reporting marker

Every harness MUST emit exactly one of these lines to the boot log on
completion:

```
[<harness>] ALL TESTS PASSED
[<harness>] SOME TESTS FAILED
```

`<harness>` is the harness name (`ktest`, `svctest`, `usertest`).

- For harnesses launched as a userspace service, `std::os::seraph::log!`
  with a name registered via `std::os::seraph::log::register_name(b"<name>")`
  produces the `[<name>]` prefix automatically; the harness payload is just
  `"ALL TESTS PASSED"` or `"SOME TESTS FAILED"`.
- For harnesses launched as the init replacement (`ktest`), logd is not
  available; the harness writes the full bracketed line directly to the
  serial port.

CI scrapes the substring `ALL TESTS PASSED` from the boot log. Per-tier
breakdown and counter lines (`PASS <name>`, `passed=`, `failed=`) are
harness-specific and MUST NOT include the bracketed summary substring.

---

## Per-program tester protocol

A program under `programs/<name>/` MAY ship a tester. Authors of each
program opt in or skip; absence is the default.

### Layout

- The tester crate lives at `programs/<name>/tester/`.
- The tester crate is a workspace member listed in the root `Cargo.toml`.
- The tester uses the standard userspace build profile (same as
  `programs/<name>/` itself).

### Install

- The tester binary lands at `/tests/programs/<name>` in the sysroot,
  regardless of the tester crate's `[[bin]]` name.
- The install path is controlled by `xtask`'s `SPECS` entry for the tester
  crate; the tester crate MUST NOT rely on its own binary name to land at
  the correct sysroot path.

### Contract

- The tester binary MUST exit `0` on pass and non-zero on fail.
- The tester binary's exit code is the authoritative verdict.
- The tester SHOULD emit a final stdout line `[<name>-tester] PASS` or
  `[<name>-tester] FAIL` for log readability. The orchestrator does not
  rely on this line for the verdict.
- The tester drives `/programs/<name>` (the program under test) through its
  real I/O surface — stdio (via `std::process::Command` with
  `Stdio::piped()`), argv, environment, filesystem — and asserts whatever
  invariant fits that program.

---

## Sysroot layout

```
sysroot/
├── services/                 # long-running userspace services
│   ├── …
│   ├── drivers/              # device drivers (cmos-rtc, goldfish-rtc,
│   │                         # virtio-blk)
│   └── fs/                   # filesystem drivers (fatfs)
├── programs/                 # production and interactive program binaries
│   ├── hello
│   ├── stdiotest
│   └── …
└── tests/                    # every test artifact (deletion criterion
    │                         # for a non-test distro shape)
    ├── ktest                 # kernel-surface harness (bootloader-loaded)
    ├── svctest               # services-surface harness
    ├── usertest              # programs-surface orchestrator
    └── programs/
        ├── hello             # per-program tester for /programs/hello
        ├── stdiotest         # per-program tester for /programs/stdiotest
        └── …
```

`/services/`, `/programs/` MUST NOT contain test harnesses or per-program
testers — all test artifacts live under `/tests/` so a non-test distro
build amounts to dropping `/tests/`.

---

## Gating

The default boot is interactive: no harness runs. It brings up the system
services and the `terminal` program, which autostarts from
`/config/svcmgr/services/terminal.svc` and is the keyboard consumer (see
[programs/terminal/README.md](../programs/terminal/README.md)).

`svcmgr` walks `/config/svcmgr/services/` and launches every `.svc` recipe
it finds (see [services/svcmgr/README.md](../services/svcmgr/README.md)).
Test-harness recipes are not shipped there by default. Instead they live
in a sibling directory that `svcmgr` does not scan:

```
rootfs/config/svcmgr/
├── services/                 # always loaded by svcmgr
│   ├── procmgr.svc
│   └── …
└── tests/                    # NOT loaded by svcmgr
    ├── svctest.svc
    ├── usertest.svc
    └── crasher.svc           # restart-path fixture; co-staged with svctest
```

To enable a harness for a boot, copy its recipe from
`sysroot/config/svcmgr/tests/` into `sysroot/config/svcmgr/services/`
between `cargo xtask build` and `cargo xtask run`:

```sh
cargo xtask build
cp sysroot/config/svcmgr/tests/svctest.svc sysroot/config/svcmgr/services/
cargo xtask run
```

`ktest` is gated separately: it lives in the bootloader-loaded bundle,
not in `svcmgr`'s recipe set. To run `ktest`, swap which binary backs
the bundle's `init` entry:

```sh
cargo xtask build
cargo xtask compose-bundle --harness ktest
cargo xtask run
```

Reset to the default-init bundle by re-running `cargo xtask build` or
`compose-bundle --harness init`. ktest's runtime options bake in as
compile-time defaults in `core/ktest/src/cmdline.rs::KtestConfig::DEFAULT`
(see [xtask/README.md](../xtask/README.md#cargo-xtask-compose-bundle)).

### Interactive input (`test-terminal`)

Keyboard input cannot be exercised by an autonomous recipe: its keysyms must
come from real `EV_KEY` events on the virtio-input device, which the guest
cannot synthesise for itself. It is also not tested by a second device reader —
the `terminal` program is the system's keyboard consumer (it autostarts from
`/config/svcmgr/services/terminal.svc`), and the virtio-input driver delivers a
given event to one reader. So input is tested *through* the terminal.

`cargo xtask test-terminal` boots QEMU with a QMP control socket, waits for the
terminal's `terminal: READY for injection` marker, injects a known key sequence
via QMP `input-send-event`, and asserts — host-side — that the terminal's local
echo and the relayed child output appear on the serial stream. Unlike the other
harnesses the verdict is computed by the host (the terminal cannot know the
expected sequence), and the host kills QEMU on success. The driver carries no
test hooks — injection happens at the hardware boundary, so the whole stack
(device DMA → decode → IPC → terminal → child → output) is exercised as in
production. Both arches use `virtio-keyboard-pci`.

The terminal autostarts on a normal boot, so no recipe staging is needed; just
build, repack, and run the host driver (not `run-parallel`, which cannot
inject):

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test-terminal
```

This is the reusable foundation for interactive tests of the terminal, the
shell (#112), and future consumers — they reuse the runner by swapping the
terminal's child and the expected strings. It subsumes the keysym-decode
coverage of the former standalone input smoke test: the echoed `a` vs `A`
proves lowercase/shifted decode, the absence of stray bytes proves
modifier-event filtering, and Return/Backspace prove the named-key decodes. In
CI it runs as a second boot inside the `usertest` cell (after usertest's own
run), rather than as a separate matrix dimension that would multiply with each
arch.

### One shutdown-invoking harness per boot

`svctest` and `usertest` invoke `pwrmgr` shutdown on completion. Two such
harnesses staged together race on shutdown — the slower one may not finish.
Per boot, at most one *shutdown-invoking* harness recipe MUST be staged in
`/config/svcmgr/services/`.

Non-shutdown fixtures may co-stage alongside one harness. `crasher`
(`restart = always`, never shuts down) is co-staged with `svctest` in
the services-surface CI cell so its restart loop is exercised there; its
bounded faults complete long before `svctest`'s terminal marker, so the
kernel fault dump never clobbers it.

**Test isolation.** The functional harness boots run a controlled substrate:
they drop the autostarted `terminal` (a user-facing program, not part of the
services/programs surface under test). Because `terminal.svc` lives in the
default service set, the harness staging removes it and repacks with
`cargo xtask mkdisk --repack-only` (a normal repack re-mirrors `rootfs/`,
which would restore it). The terminal is exercised in its own boot
(`test-terminal`) and runs in the real default boot.

CI matrix cells follow these rules per boot. The `usertest` cell runs two
boots in sequence — `usertest` (via `run-parallel`, terminal dropped), then
the terminal interactive test (via `test-terminal`) after dropping
`usertest.svc` and repacking to restore the default boot (terminal present).
The terminal test boot has *no* shutdown-invoking harness: `test-terminal`
computes the verdict host-side and kills QEMU itself.

---

## Cross-harness conventions

- **Completion behavior.** A harness MUST request `pwrmgr` shutdown when
  it finishes (pass or fail). This terminates the QEMU instance and lets
  CI move on. Harnesses launched as services obtain the shutdown
  capability via the `pwrmgr.shutdown` and `pwrmgr.deny` seeds in their
  `.svc` recipe.
- **Restart policy.** A harness MUST set `restart = never` in its `.svc`
  recipe. Re-running on accidental exit corrupts CI semantics.
- **Critical class.** A harness MUST set `critical = no`. Harness death
  MUST NOT bring down the supervisor or trip the graceful-shutdown path.
- **Capability seeding.** A harness depends only on seeds declared in
  its `.svc` recipe. The harness MUST log its own seed-resolution state
  before running tests, so failures attributable to missing capabilities
  are diagnosable.

---

## Historical naming

The identifier `usertest` formerly named the services-tier harness, which
lived at `base/usertest/`. The rename pass that landed under PR #119
relocated that harness to `services/svctest/`, freeing the `usertest`
name. As of this document, `usertest` is the programs-surface
orchestrator at `services/usertest/`. References to `usertest` in commit
history before that rename refer to the prior services-tier harness.

See [conventions.md](conventions.md) for the original historical-naming
note in full.

---

## Summarized By

[Conventions](conventions.md), [Root README](../README.md), [core/ktest/README.md](../core/ktest/README.md), [services/svcmgr/README.md](../services/svcmgr/README.md), [services/usertest/README.md](../services/usertest/README.md), [programs/terminal/README.md](../programs/terminal/README.md)
