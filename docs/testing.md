# Testing

System-wide standard for the in-tree test harnesses, the per-program tester
protocol, the sysroot layout for test binaries, and the gating mechanism
that determines which harnesses run in a given boot.

This document covers booted functional testing. Host-side `#[cfg(test)]` unit
tests — their quality rules and the boundary between host-unit and booted
testing — are governed by
[coding-standards.md](coding-standards.md#d-testing-invariants).

---

## Harnesses

Three harnesses exercise three surfaces:

| Harness | Surface | Crate | Launch mechanism |
|---|---|---|---|
| `ktest` | Kernel | [`core/ktest/`](../core/ktest/README.md) | Bootloader-loaded init replacement (`cargo xtask compose-bundle --harness ktest`) |
| `svctest` | Services | `services/svctest/` | `svcmgr` spawns from `/config/svcmgr/services/` recipe |
| `usertest` | Programs | [`services/usertest/`](../services/usertest/README.md) | `svcmgr` spawns from `/config/svcmgr/services/` recipe; drives binaries under `programs/` through their real I/O surfaces. Also hosts the terminal interactive test (`cargo xtask test-terminal`), which drives the autostarted terminal through both input sources — keys over QMP through the live virtio-input driver, then the same sequence over the guest serial RX |

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
- The tester binary's exit code is the authoritative verdict. Seraph propagates
  it natively: `sys_process_exit` encodes the code into the calling thread's
  exit reason via `syscall_abi::encode_exit_code` (codes `1..0x0FFF`, saturating),
  which the orchestrator reads through `ExitStatus::success()`/`code()`. This is a
  native flat encoding, not POSIX `WEXITSTATUS` — no 8-bit truncation.
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

Interactive input cannot be exercised by an autonomous recipe: keysyms must come
from real `EV_KEY` events on the virtio-input device, and serial bytes from a
real UART receive, neither of which the guest can synthesise for itself. Input
is also not tested by a second device reader — the `terminal` program is the
system's input consumer (it autostarts from
`/config/svcmgr/services/terminal.svc`), and each device delivers a given event
to one reader. So input is tested *through* the terminal.

`cargo xtask test-terminal` boots QEMU with a QMP control socket, waits for the
terminal's `terminal: READY for injection` marker, then drives both input
sources in one boot:

1. **Keyboard round** — inject a known key sequence via QMP `input-send-event`
   (through the live `virtio-keyboard-pci`), assert the terminal's local echo
   and the relayed child output appear on the serial stream.
2. **Serial RX round** — on a cleared transcript, write the same sequence to the
   guest UART receive path via QEMU's bidirectional `-serial stdio` (host stdin
   reaches the guest serial RX), assert the same echo + child round-trip.

Unlike the other harnesses the verdict is computed by the host (the terminal
cannot know the expected sequence), and the host kills QEMU on success. The
driver carries no test hooks — injection happens at the hardware boundary, so
the whole stack (device → decode/IRQ → IPC → terminal → child → output) is
exercised as in production. Both rounds run on both arches.

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

## Coverage tiers

The matrix CI exercises is exhaustive in three dimensions and fixed in the
rest. Coverage is tiered so the fixed dimensions still get exercised — just
not on every push.

**Dimension inventory.** Exhaustive per CI run: architecture (x86_64,
riscv64) × profile (debug, release) × harness (ktest, svctest, usertest).
Fixed per CI run: vCPU count (4), guest memory (512 MiB), device set
(virtio-blk + virtio-keyboard + serial; CI boots headless, so no
framebuffer), filesystem (FAT), riscv64 paging mode (sv48 — per-mode runs
via `cargo xtask run --riscv-mmu sv39|sv57` are manual, same posture as
CPU-count variations).
A device or filesystem joining the default boot set joins the canonical
cells automatically; variants belong to the tiers below.

| Tier | Where | When | Coverage |
|---|---|---|---|
| Canonical | `build-test.yml` | every push / PR | full arch × profile × harness at the fixed defaults |
| Burn-in | `burnin.yml` | tag push; manual dispatch on any ref | canonical cells × 20 iterations, 2-way parallel |
| Local host runs | developer host, commands below | REQUIRED for PRs touching SMP, per-CPU, IPI, scheduler-wakeup, boot, or memory-init paths | CPU-count and memory variations CI runners cannot reach |

**Why local-only.** Hosted CI runners are ~4-vCPU TCG-only machines; a
65-vCPU guest is a ~16× thread oversubscription and a 512-vCPU guest is
infeasible there. High `-smp` coverage is local by design, not an
oversight. The runs below are procedurally REQUIRED for PRs touching the
listed paths — binding the same way the pre-merge audit agents are, with
no CI surface.

```sh
# Boundary CPU counts, riscv64 (~70 s per passing run on a 16-core host;
# the 600 s budget is for HANG classification):
cargo xtask build --arch riscv64
cargo xtask compose-bundle --harness ktest --arch riscv64
cargo xtask run-parallel --arch riscv64 --cpus 64 --parallel 1 --runs 3 --timeout 600
cargo xtask run-parallel --arch riscv64 --cpus 65 --parallel 1 --runs 3 --timeout 600

# Boundary CPU counts, x86_64 (~330 s per passing run on a 16-core KVM
# host — boot is seconds, but the stress tier runs at 16x vCPU
# oversubscription; the 900 s budget is for HANG classification):
cargo xtask build
cargo xtask compose-bundle --harness ktest
cargo xtask run-parallel --arch x86_64 --cpus 256 --parallel 1 --runs 3 --timeout 900

# Memory variation (either arch):
cargo xtask run-parallel --arch <arch> --cpus 4 --mem 1024 --parallel 1 --runs 1 --timeout 300
```

PRs touching the surfaces that only matter above 256 CPUs — `core/kernel/src/mm/`,
x86_64 AP bringup (`arch/x86_64/ap_trampoline.rs`, `arch/x86_64/gdt.rs`, the
APIC/IPI paths in `arch/x86_64/interrupts.rs`), or per-CPU slab sizing
(`sched::alloc_zeroed_slab` and its call sites) — MUST additionally run the
full-width x86_64 boundary below. This trigger list is deliberately narrow;
other SMP PRs stay on the 256-vCPU mandate above.

```sh
# MAX_CPUS boundary, x86_64 (~16 min per passing run measured on a 16-core KVM
# host at 32x vCPU oversubscription, down from ~105 min before #380 made
# thread_set_priority's locate-and-relocate O(1) in the common case; the
# residual is dominated by 512-vCPU AP bringup and the broadcast/IPI stress
# tests, not the priority walk. The 3600 s budget is for HANG classification):
cargo xtask run-parallel --arch x86_64 --cpus 512 --parallel 1 --runs 1 --timeout 3600
```

PRs touching the bootloader's kernel-placement path — `core/boot/src/elf.rs`
(kernel ELF span allocation), `core/boot/src/uefi.rs` (UEFI page allocation),
or the boot page-table builders (`core/boot/src/paging.rs`,
`core/boot/src/arch/*/paging.rs`) — MUST additionally run the riscv64 128-hart
boundary below. It is the riscv64 analogue of the full-width x86_64 run: the
hart count at which hart-scaled firmware allocations once collided with the
kernel image's load address ([#377](https://github.com/kottlerg/seraph/issues/377)).
This trigger list is deliberately narrow; other SMP PRs stay on the 64/65-hart
mandate above.

```sh
# Kernel-placement boundary, riscv64 (~475 s per passing run measured at 8x hart
# oversubscription on a 16-core host; the 1800 s budget is for HANG
# classification):
cargo xtask run-parallel --arch riscv64 --cpus 128 --parallel 1 --runs 1 --timeout 1800
```

**Known boundaries**, established empirically (QEMU 11.0.1; update this
list as the tracking Issues move):

- x86_64 > 256 CPUs ([#376](https://github.com/kottlerg/seraph/issues/376),
  fixed): the per-CPU boot slabs (`AP_IST_STACKS`, `AP_TSS`) exceeded the
  buddy allocator's old `MAX_ORDER = 10` single-allocation cap (4 MiB) at
  257+ CPUs, failing Phase 4 regardless of guest memory size. `MAX_ORDER`
  is now 11 (8 MiB — exactly `AP_IST_STACKS` at `MAX_CPUS = 512`), with
  compile-time asserts at the slab consumer sites so the envelope breaks
  the build, not the boot. The full 512-vCPU width is exercised by the
  MAX_CPUS boundary run above.
- riscv64 ≥ 128 harts ([#377](https://github.com/kottlerg/seraph/issues/377),
  fixed): boot died in UEFI (`ConvertPages: Incompatible memory types`) while
  loading the kernel ELF, because the bootloader requested the image at a fixed
  `p_paddr` (`0x80200000`) that hart-scaled firmware allocations had already
  claimed — independent of guest memory size. The kernel image is now placed as
  one contiguous span allocated anywhere (`AllocateAnyPages`), so loading
  tolerates any firmware layout; `validate_kernel_layout` enforces the
  relocation invariants (single offset, alignment, non-overlap, entry-in-image)
  at load time. 128 harts now boots clean (3×, ~475 s/run at 8× hart
  oversubscription on a 16-core host). The residual ceiling is upstream and
  pre-bootloader: at 192, 256, and 512 harts under TCG the edk2 firmware emits
  no serial output at all (192: nothing in 60 min; 256/512: nothing in 20/30
  min) — an MP-init crawl that runs before Seraph's bootloader and cannot be
  addressed in-tree. High-hart cross-architecture parity is therefore
  theoretical, with real testing on hold pending faster firmware, KVM-capable
  RISC-V emulation, or real hardware.
- Both arches, high CPU counts ([#375](https://github.com/kottlerg/seraph/issues/375),
  fixed): the intermittent silent wedge around the `thread::load_balancer`
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
  into the fewest contiguous Memory caps before minting, so the descriptor
  count tracks memory-map fragmentation (a small fixed number of usable extents
  plus reservation holes), not total RAM. The Phase-9 size check now logs the
  descriptor count, page need, and `INIT_INFO_MAX_PAGES` before fatal-ing, so
  any residual overflow on a pathologically fragmented map is diagnosable rather
  than bare. Verified booting clean to the ktest pass marker on both arches at
  `--mem 4096`.

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

[Conventions](conventions.md), [Root README](../README.md), [core/ktest/README.md](../core/ktest/README.md), [services/svcmgr/README.md](../services/svcmgr/README.md), [services/usertest/README.md](../services/usertest/README.md), [programs/terminal/README.md](../programs/terminal/README.md), [programs/shell/README.md](../programs/shell/README.md)
