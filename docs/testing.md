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
| `svctest` | Services | [`services/svctest/`](../services/svctest/README.md) | `svcmgr` spawns from `/config/svcmgr/services/` recipe |
| `usertest` | Programs | [`services/usertest/`](../services/usertest/README.md) | `svcmgr` spawns from `/config/svcmgr/services/` recipe; drives binaries under `programs/` through their real I/O surfaces. The terminal interactive test (`cargo xtask test-terminal`) runs as a separate boot in the `usertest` CI cell; it drives the autostarted terminal through both input sources — keys over QMP through the live virtio-input driver, then the same sequence over the guest serial RX |

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
  it natively, without POSIX 8-bit truncation (see
  [syscalls.md § `SYS_PROCESS_EXIT`](../core/kernel/docs/syscalls.md#sys_process_exit-54));
  the orchestrator reads it through `ExitStatus::success()`/`code()`.
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
│   ├── drivers/              # device drivers (virtio-blk, virtio-input,
│   │                         # serial, framebuffer, cmos-rtc | goldfish-rtc,
│   │                         # and the test-only test-orphan)
│   └── fs/                   # filesystem drivers (fatfs)
├── programs/                 # program binaries and the test fixtures the
│                             # harnesses spawn
│   ├── hello
│   ├── stdiotest
│   └── …
└── tests/                    # test harnesses, per-program testers, and
    │                         # harness-only fixtures
    ├── ktest                 # kernel-surface harness (bootloader-loaded)
    ├── svctest               # services-surface harness
    ├── usertest              # programs-surface orchestrator
    ├── crasher               # svcmgr restart-path fixture
    └── programs/
        ├── hello             # per-program tester for /programs/hello
        ├── stdiotest         # per-program tester for /programs/stdiotest
        └── …
```

`/services/` and `/programs/` MUST NOT contain test harnesses or per-program
testers; those live under `/tests/`. Dropping `/tests/` does not by itself
give a non-test distro, because test-only artifacts also install under
`/services/drivers/`, `/programs/`, `/config/svcmgr/tests/`, and `/data/`.
Under `/services/drivers/` is
[`test-orphan`](../services/drivers/test-orphan/README.md), a test-only
fault-injection driver installed there until the devmgr enumeration
redesign ([#165](https://github.com/kottlerg/seraph/issues/165)) removes
it. Under `/programs/` are the test fixtures the harnesses and per-program
testers spawn: `capexhaust`, `demandpaged`, `fsbench`, `pipefault`, `pipestress`,
`relrofault`, `stackoverflow`, `stdiotest`, `threadchurn`, and `threadstack`. Which
consumer spawns or drives each one is owned by
[services/svctest/README.md § Fixtures](../services/svctest/README.md#fixtures) for
`svctest` phases and by each fixture's README (`programs/<name>/README.md`) for every
per-program tester that drives it. Under `/config/svcmgr/tests/` are the harness
recipes (see [Gating](#gating)). Under `/data/` are `/data/test.txt`, a fixture shared
by `svctest` and the `shell` tester, and the build-synthesised `svctest`-only fixtures
`/data/svctest/large.bin` and `/data/svctest/bench.bin`.

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
`sysroot/config/svcmgr/tests/` into `sysroot/config/svcmgr/services/` after
`cargo xtask build`, then repack with `cargo xtask mkdisk --repack-only` before
`cargo xtask run` (`run` boots the existing `disk.img`, and a normal `mkdisk`
re-mirror prunes the hand-staged recipe):

```sh
cargo xtask build
cp sysroot/config/svcmgr/tests/svctest.svc sysroot/config/svcmgr/services/
cargo xtask mkdisk --repack-only
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
sources in one boot (command reference:
[xtask/README.md § test-terminal](../xtask/README.md#cargo-xtask-test-terminal)):

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
coverage of the former standalone input smoke test: the echoed `help` proves
lowercase keysym decode, and Return/Backspace prove the named-key decodes. In
CI it runs as a second boot inside the `usertest` cell (after usertest's own
run), rather than as a separate matrix dimension that would multiply with each
arch.

### Snapshot resume (`test-vmgenid`)

Whole-VM-snapshot reseed (#395) cannot be exercised by an in-guest recipe: the
generation change only happens when the hypervisor restores saved state, and
QEMU deliberately exposes no QMP/HMP way to change the GUID at runtime.
`cargo xtask test-vmgenid` (x86_64 only — QEMU's riscv64 `virt` machine has no
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

See [xtask/README.md § test-vmgenid](../xtask/README.md#cargo-xtask-test-vmgenid)
for the command and [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)
for the snapshot-detection design.

Same boot requirements as `test-terminal` (default boot set, terminal
autostarted); the host computes the verdict and kills QEMU. In CI it runs as
an additional boot inside the x86_64 `usertest` cell, after `test-terminal`.

### KASLR randomization (`test-kaslr`)

KASLR (#252) cannot be verified from inside the guest: it must observe that the
layout *differs* across separate boots. `cargo xtask test-kaslr [--arch]` (both
arches) drives this host-side against the ktest bundle:

1. Boot twice with KASLR enabled; scrape the kernel's serial-only
   `kaslr: slide=… image_base=… dm_base=…` line (emitted in Phase 1) and assert
   the joint `(slide, dm_base)` differs between the two boots. A single-dimension
   collision is ~1/1000, so the compare is joint and retries boot B once — a
   false failure is ~1e-8.
2. Stage the `\EFI\seraph\nokaslr` override knob, repack `disk.img`, boot once,
   and assert the deterministic layout (slide 0, image at its link base, direct
   map at the mode floor); the KASLR-enabled image is always restored afterward.

See [xtask/README.md § test-kaslr](../xtask/README.md#cargo-xtask-test-kaslr) for
the command and [memory-model.md](memory-model.md) for the randomized layout.

Requires a populated sysroot with the ktest bundle composed
(`cargo xtask compose-bundle --harness ktest`). The `kaslr:` line is emitted only
through the kernel's serial-only console class (see
[cross-boundary-disclosure.md § Kernel console diagnostics](../core/kernel/docs/cross-boundary-disclosure.md#kernel-console-diagnostics)).
In CI it runs as extra boots inside each `ktest` cell (both arches, both
profiles), after the `ktest` run-parallel boot.

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

CI matrix cells follow these rules per boot. The `usertest` cell runs its
boots in sequence — `usertest` (via `run-parallel`, terminal dropped), then
the terminal interactive test (via `test-terminal`) after dropping
`usertest.svc` and repacking to restore the default boot (terminal present),
then on x86_64 the `test-vmgenid` save/restore boot pair.
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
(virtio-blk + virtio-keyboard + virtio-rng + serial, plus `vmgenid,guid=auto`
on x86_64; CI boots headless, so no framebuffer), filesystem (FAT), riscv64
paging mode (sv48 — per-mode runs via `cargo xtask run --riscv-mmu sv39|sv57`
are manual, same posture as CPU-count variations). The `virtio-rng` device is
a boot-entropy source for the pool seed and KASLR: the firmware's RNG driver
binds it and exposes `EFI_RNG_PROTOCOL`, which the bootloader draws from (OVMF
also backs the protocol with RDRAND on x86_64; on riscv64 the device is the
only firmware source under the EDK2 firmware CI boots, and the pool mixes
jitter besides; see
[core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
A device or filesystem joining the default boot set joins the canonical
cells automatically; variants belong to the tiers below.

| Tier | Where | When | Coverage |
|---|---|---|---|
| Canonical | `build-test.yml` | every push / PR | full arch × profile × harness at the fixed defaults |
| Burn-in | `burnin.yml` | tag push; manual dispatch on any ref | each canonical arch × profile × harness `run-parallel` boot × 20 iterations, 2-way parallel (no `crasher` co-staging, no host-driven `test-*` boots) |
| Local host runs | developer host, commands below | REQUIRED for a PR whose own diff changes the CPU-count or memory surface, or that states a concurrency-fix purpose as Repeat count defines it and makes a non-inert change (see Boundary surface, Memory surface, and Repeat count below), once per PR (see When the runs are owed below) | CPU-count and memory variations CI runners cannot reach |
| Release host runs | maintainer host, commands below | before each tag, on the commit to be tagged | every boundary below (riscv64 64, 65, and 128 harts; x86_64 256 and 512 vCPUs) and the memory variation, whatever the release's PRs touched (see Release host runs below) |

**Why local-only.** Hosted CI runners are ~4-vCPU TCG-only machines; a
65-vCPU guest is a ~16× thread oversubscription and a 512-vCPU guest is
infeasible there. High `-smp` coverage is local by design, not an
oversight. The local host runs below are procedurally REQUIRED for the PRs
that owe them, and the release host runs for each tag —
binding the same way the
[pre-merge review](conventions.md#branch-and-pr-workflow) is, with no CI
surface.

**Inert changes.** A change that alters only the following cannot change behaviour at any CPU count
or memory size, and owes no local host run, whatever file it is in:

- Markdown, and comment lines in source files, build scripts, and linker scripts;
- lint attributes: `#[allow(...)]`, `#[expect(...)]`, `#[warn(...)]`, `#[deny(...)]`, their inner
  `#![...]` forms, and a `#[cfg_attr(<predicate>, <lint attribute>)]`;
- code compiled only for host tests: a `#[cfg(test)]` module or item, or a `#[test]` function;
- the deletion of a named function, constant, static, or type (not a module, an `impl` block, or
  a trait-method implementation) that nothing names at the PR head outside comments and Markdown
  (`git grep -w <name> <head>` finds no other use) and that carries no attribute making it
  reachable without its name (`no_mangle`, `export_name`, `used`, `link_section`,
  `global_allocator`, or `panic_handler`, in any form: plain, `unsafe(...)`, or under
  `cfg_attr`).

A PR whose changes outside Markdown are all inert owes no local host run, whatever purpose it
states. The surfaces below, and Repeat count, are judged on the non-inert lines only.

**Boundary surface.** The boundary set below is owed when, and only when, the PR's own diff (see
When the runs are owed below) makes a non-inert change to the CPU-count surface; a stated
concurrency-fix purpose owes three of its boundaries on its own (see Repeat count below). The
CPU-count surface is the code that fixes the CPU-count width, enumerates and brings up CPUs, sizes
per-CPU storage, or signals across CPUs, and it is exactly what this paragraph lists. Code that only
reads `CPU_COUNT` or a `cpu_count` argument to iterate over CPUs is not on it unless it lies in a
whole-surface file, names a listed item, or lies within one's definition; the rules of
[coding-standards.md](coding-standards.md) § CPU-Count Width and the release host runs cover it. The
surface is these files as a whole:

- `core/kernel/src/cpu_mask.rs` (the CPU mask type and its width);
- `core/kernel/src/percpu.rs` (per-CPU data and its slabs);
- `core/kernel/src/arch/x86_64/ap_trampoline.rs` and `core/kernel/src/arch/riscv64/ap_trampoline.rs`
  (AP and hart bringup);
- `core/kernel/src/mm/tlb_shootdown.rs` (the TLB-shootdown broadcast);
- `core/kernel/src/mm/tag_allocator.rs` (the per-CPU address-space tags, whose count it fits to
  the CPU count);

and, in any other file, a line that adds a structure with one entry or one bit per CPU, and a
changed line that names one of these items as a whole identifier or lies within one's definition
(its attributes, signature, fields, or body):

- CPU-count width: `MAX_CPUS`, `CpuMask`, `CPU_MASK_WORDS`;
- per-CPU storage: `alloc_zeroed_slab`, and the definition of every function that calls it (the
  per-CPU storage initialisers; a call to one is on the surface only when it names another listed
  item, as a call to an `init_ap_*` initialiser does); every `init_storage` and
  `init_per_cpu_storage`, which take the boot CPU count and size per-CPU storage from it (a call to
  one names it, so a change to the count it passes is on the surface); `kernel_reserve_pages` (the
  CPU-scaled kernel reserve); and the element types of the per-CPU arrays and slabs, today
  `PerCpuData`, `PerCpuScheduler`, `ThreadControlBlock` (through `MaybeUninit`), `TssWithIopb`,
  `TagState`, `CpuRng`, `Acc`, `Sample`, and `TlbShootdownRequest` (`git grep -n -E
  'alloc_zeroed_slab::<|; MAX_CPUS\]' <head>` lists the arrays and slabs, and also the single-slot
  entropy pool slab, which is not per-CPU). A change that alters an element type's size is on the
  surface whether it edits the type's own fields or a type or constant the element holds by value
  (for example `RunQueue` and `NUM_PRIORITY_LEVELS` inside `PerCpuScheduler`, or `Prng` inside
  `CpuRng`), and so is a change to a constant that sizes a per-CPU allocation (`KERNEL_STACK_PAGES`
  for the idle stacks);
- CPU enumeration and bringup: in the bootloader, `parse_cpu_topology`, `parse_madt_topology`
  and the MADT walk behind it (`madt_topology` and its per-CPU `record_cpu_id`),
  `parse_cpu_count`, `step5_discover_cpu_topology`, `single_cpu_topology`, `CpuTopology`,
  `discover_boot_hart_id` and `bsp_hardware_id` (the source of the BSP id that becomes
  `cpu_ids[0]`), and the handoff of the count and the CPU ids into `BootInfo` (`cpus.count` and
  `cpus.cpu_ids`); in the kernel, the boot CPU count and ids (`info.cpu_count`, `info.cpu_ids`,
  `boot_cpu_count`, and `boot_cpu_ids`), `start_ap`, `sbi_hart_start`, `kernel_entry_ap`, every
  `init_ap`, and the `init_ap_*` per-CPU storage initialisers;
- IPI send and receive: `send_wakeup_ipi`, `send_tlb_shootdown_ipi`, `send_init_ipi`, `send_sipi`,
  `send_nmi_to`, `sbi_send_ipi_to`, `sbi_hart_mask`, `wait_for_ack`, `IpiWaitCtx`, the
  `IPI_VECTOR_*` constants, the x86_64 `ipi_*` stubs and handlers in `idt.rs`, the x86_64 ICR and
  x2APIC primitives and the mode they set (`apic_send_icr`, `wait_icr_idle`,
  `enable_x2apic_this_cpu`, `X2APIC_ENABLED`, `x2apic_supported`, `x2apic_enabled`,
  and `x2apic_wrmsr_fence`), and the riscv64 `handle_software_interrupt`;
- the TLB-shootdown broadcast: `shootdown`, `shootdown_range`, `service_shootdowns`,
  `shootdown_remote`, and `needs_remote_shootdown`.

A change anywhere else, however close to the scheduler or the SMP paths, is off the surface. A PR
that adds an item of the kinds above that names none of the listed items MUST add it to this list.
The commands below screen a diff for the surface. The first lists the whole-surface files the diff
changes. The second prints every file header of the diff and every line, changed or context, that
names a listed item; `-W` widens each hunk to its whole enclosing item, so a change inside a listed
item's definition prints that item's name. Each printed name is a candidate: the PR owes the set
when a non-inert changed line names the item or lies within its definition, read in that file's
hunk. A printed `alloc_zeroed_slab` call is a candidate for the initialiser that encloses it: the
set is owed when a non-inert changed line lies within that function, read in the widened hunk. The
screen finds named items and changes inside their definitions; it does not follow a size
change through a nested type or a sizing constant, so a diff that changes a struct's fields or a
constant's value is also read against the per-CPU storage bullet (`git grep -n -w <name> <head>`
shows where the type or constant is held). A diff for which neither command prints a candidate,
that adds no per-CPU structure, and whose type and constant changes reach no per-CPU element or
allocation is off the surface.

```sh
B=$(git merge-base <head> origin/master)
git diff --stat "$B" <head> -- core/kernel/src/cpu_mask.rs core/kernel/src/percpu.rs \
    core/kernel/src/mm/tlb_shootdown.rs core/kernel/src/mm/tag_allocator.rs \
    'core/kernel/src/arch/*/ap_trampoline.rs'
S='MAX_CPUS|CpuMask|CPU_MASK_WORDS|alloc_zeroed_slab|init_storage|init_per_cpu_storage'
S="$S|kernel_reserve_pages|boot_cpu_count|PerCpuData|PerCpuScheduler|ThreadControlBlock"
S="$S|TssWithIopb|TagState|CpuRng|Acc|Sample|TlbShootdownRequest|CpuTopology"
S="$S|parse_cpu_topology|parse_madt_topology|madt_topology|record_cpu_id|parse_cpu_count"
S="$S|single_cpu_topology|cpus\.count|cpus\.cpu_ids|info\.cpu_count|info\.cpu_ids|boot_cpu_ids"
S="$S|step5_discover_cpu_topology|start_ap|discover_boot_hart_id|bsp_hardware_id"
S="$S|sbi_hart_start|kernel_entry_ap|init_ap(_[a-z_]+)?|send_(wakeup|tlb_shootdown|init)_ipi"
S="$S|send_sipi|send_nmi_to|sbi_send_ipi_to|sbi_hart_mask|wait_for_ack|IpiWaitCtx"
S="$S|IPI_VECTOR_[A-Z_]+|ipi_[a-z_]+_(stub|handler)|apic_send_icr|wait_icr_idle"
S="$S|enable_x2apic_this_cpu|X2APIC_ENABLED|x2apic_supported|x2apic_enabled"
S="$S|x2apic_wrmsr_fence"
S="$S|handle_software_interrupt"
S="$S|shootdown(_range|_remote)?|service_shootdowns|needs_remote_shootdown"
git diff -W "$B" <head> -- . ':(exclude)*.md' | grep -E "^\+\+\+ |\b($S)\b"
```

The boundary set is every boundary CPU count below, each once (`--runs 1`, raised only as Repeat
count says): riscv64 64, 65, and 128 harts, and x86_64 256 and 512 vCPUs.

```sh
# Boundary CPU counts, riscv64 (the 64- and 65-hart runs take ~70 s each
# on a 16-core host, the 128-hart run ~2-3 min at 8x hart oversubscription;
# the 600 s and 1800 s budgets are for HANG classification):
cargo xtask build --arch riscv64
cargo xtask compose-bundle --harness ktest --arch riscv64
cargo xtask run-parallel --arch riscv64 --cpus 64 --parallel 1 --runs 1 --timeout 600
cargo xtask run-parallel --arch riscv64 --cpus 65 --parallel 1 --runs 1 --timeout 600
cargo xtask run-parallel --arch riscv64 --cpus 128 --parallel 1 --runs 1 --timeout 1800

# Boundary CPU counts, x86_64 (the 256-vCPU run takes ~2 min on a 16-core
# KVM host at 16x vCPU oversubscription. The 512-vCPU run, the MAX_CPUS
# boundary, takes ~28 min at 32x, where every cross-CPU step waits for a
# host core and the stress tier takes about three quarters of the run. The
# 900 s and 3600 s budgets are for HANG classification):
cargo xtask build
cargo xtask compose-bundle --harness ktest
cargo xtask run-parallel --arch x86_64 --cpus 256 --parallel 1 --runs 1 --timeout 900
cargo xtask run-parallel --arch x86_64 --cpus 512 --parallel 1 --runs 1 --timeout 3600
```

The 65-hart run is the first count past a 64-bit word; the 128-hart run is the count at which
hart-scaled firmware allocations once collided with the kernel image's load address
([#377](https://github.com/kottlerg/seraph/issues/377)); the 512-vCPU run is `MAX_CPUS`.

Past 16 CPUs ktest scales its round-based stress cells' attempt counts, and stretches the
wall-clock bounds [core/ktest/README.md § Tier S](../core/ktest/README.md#tier-s--srcstress) lists,
by the oversubscription factor the width implies, so the boundary runs stay inside their budgets
while the CI widths keep the full counts and tight budgets.

**Memory surface.** The memory variation below is owed when, and only when, the PR's own diff makes
a non-inert change to the memory surface: the code that sizes or maps physical memory by the
guest's RAM, exactly as listed here. It is `core/kernel/src/mm/buddy.rs` and
`core/kernel/src/mm/init.rs` as a whole, and, in any other file, a changed line that names, or lies
within the definition of, one of these items: the boot memory map and the direct map
(`translate_memory_map`, `max_ram_address`, `direct_map_ceiling`, `compute_max_physical_address`,
`init_kernel_page_tables`, and `BOOT_TABLE_POOL_SIZE`), and the drain of RAM into Memory caps
(`drain_and_install_seed`, `MAX_DRAIN_BLOCKS`, `populate_cspace`, and
`INIT_INFO_MAX_PAGES`), the frame map table's DRAM-span sizing (`dram_bounds`, `DRAM_BOUNDS`,
`frame_map::init`, and `CHUNK_ORDER`), and the `CSpace` registry arena's RAM sizing
(`init_cspace_registry`, `chunks_for_ram`, and `REGISTRY_CHUNK_ORDER`). The screen works as the
boundary one does:

```sh
git diff --stat "$B" <head> -- core/kernel/src/mm/buddy.rs core/kernel/src/mm/init.rs
M='translate_memory_map|max_ram_address|direct_map_ceiling|compute_max_physical_address'
M="$M|init_kernel_page_tables|BOOT_TABLE_POOL_SIZE|drain_and_install_seed"
M="$M|MAX_DRAIN_BLOCKS|populate_cspace|INIT_INFO_MAX_PAGES"
M="$M|dram_bounds|DRAM_BOUNDS|frame_map::init|CHUNK_ORDER"
M="$M|init_cspace_registry|chunks_for_ram|REGISTRY_CHUNK_ORDER"
git diff -W "$B" <head> -- . ':(exclude)*.md' | grep -E "^\+\+\+ |\b($M)\b"

# Memory variation (either arch):
cargo xtask run-parallel --arch <arch> --cpus 4 --mem 1024 --parallel 1 --runs 1 --timeout 300
```

**Repeat count.** Every owed run runs once (`--runs 1`). A PR states a concurrency-fix purpose when
its body states that its purpose is the fix of a concurrency defect in the scheduling, wake, or
cross-CPU signalling mechanisms. Such a PR, unless its changes outside Markdown are all inert, owes
the riscv64 64- and 65-hart and the x86_64 256-vCPU boundaries three times each (`--runs 3`),
whether or not its diff changes the CPU-count surface: a race in those mechanisms can fail rarely
enough that one run misses it. That PR's other owed runs stay at `--runs 1`. A concurrency fix
elsewhere is not a concurrency-fix purpose, and a change to those mechanisms' files without that
stated purpose does not raise the count.

**When the runs are owed.** Each local host run a PR owes MUST pass, at its repeat count, at one
head that covers the merge head. For every local and release host run, only a `PASS` outcome of
`run-parallel` ([xtask/README.md](../xtask/README.md)) passes; a `QEMU-CRASH` run, a crash of the
host emulator, is run again and the re-run's outcome stands; `OK` and `ERR` count as failures. The
PR's own diff at a head is the diff from that head's merge base with the fetched `master` to the
head (after `git fetch origin`, `git diff $(git merge-base <head> origin/master) <head>`), so it
excludes what a merge or rebase from `master` brings in. A run's surface is the surface that owes
it: the CPU-count surface for the boundary set, the memory surface for the memory variation, and,
for the runs a concurrency-fix purpose owes, every non-inert line of the PR's own diff. A run at
head H covers a later head M when the PR's own diff makes the same non-inert changes to that run's
surface at H and at M. An update from `master` that leaves those changes as they were therefore owes
no run; one whose conflict resolution alters them does. A fix round that alters them breaks the
coverage of the runs that surface owes, and those runs MUST be run again at a head after it. The PR
body MUST report each run it owes with its `--runs` count, its outcome, and the head it ran at, or
state that none is owed and why: that its changes outside Markdown are all inert, or that its
non-inert lines change neither surface and it states no concurrency-fix purpose as Repeat count
defines it.

**Hangs at oversubscription.** A boundary run the PR does not owe, that is, one whose surface the
PR's own diff does not change, that HANGs (outlives its `--timeout` budget) or fails with a defect
an open Issue for that boundary already names is not the PR's defect: the preserved log is recorded
on the open Issue for that boundary (today [#421](https://github.com/kottlerg/seraph/issues/421)
for the x86_64 high-smp budget overruns and [#455](https://github.com/kottlerg/seraph/issues/455)
for the 512-vCPU IPI watchdog), or on a new Issue when that boundary has none, and the run does not
block the PR. The PR body reports such a run as HANG or FAIL with a link to that record. Any other
HANG or failure of a run the PR does not owe (a memory-variation HANG or failure, or a boundary
failure no open Issue for that boundary names), and any HANG or failure of a run the PR owes,
blocks the PR.

**Release host runs.** Before each tag
([conventions.md](conventions.md#release-production) § Release Production, step
4), the maintainer MUST run, on the commit to be tagged, the riscv64 64- and
65-hart and the x86_64 256-vCPU boundaries three times each (`--runs 3`), the
riscv64 128-hart and the x86_64 512-vCPU boundaries once each, and the memory
variation once, so every tag boots at each boundary CPU count. A run whose
outcome is not a pass, as When the runs are owed classifies outcomes, blocks the
tag, MUST be filed as an Issue, and is bisected over the release's PRs.

**Documentation-only and comment-only changes.** A diff that, Markdown
aside, alters only comment lines in source files cannot change program
behaviour other than the source positions that `#[track_caller]`, `line!()`,
and `column!()` record and assertion messages carry, which the CI gate's
boots cover, so none of the local host runs in this section are required for
it, whatever paths it touches. Source text a build embeds verbatim
(`include_str!`, `include_bytes!`, `global_asm!` inputs) is build input, not
comment or Markdown. The CI gate and the
[pre-merge review](conventions.md#branch-and-pr-workflow) apply unchanged;
the PR body MUST carry what
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
  plus reservation holes), not total RAM. The Phase-9 size check now logs the
  descriptor count, page need, and `INIT_INFO_MAX_PAGES` before fatal-ing, so
  any residual overflow on a pathologically fragmented map is diagnosable rather
  than bare. Verified booting clean to the ktest pass marker on both arches at
  `--mem 4096`.

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

[README.md](../README.md), [Kernel Entropy Subsystem](../core/kernel/docs/entropy.md),
[core/ktest/README.md](../core/ktest/README.md), [Build System](build-system.md),
[Console Model](console-model.md), [Project Conventions](conventions.md),
[programs/capexhaust/README.md](../programs/capexhaust/README.md),
[programs/demandpaged/README.md](../programs/demandpaged/README.md),
[programs/fsbench/README.md](../programs/fsbench/README.md),
[programs/hello/README.md](../programs/hello/README.md),
[programs/pipefault/README.md](../programs/pipefault/README.md),
[programs/pipestress/README.md](../programs/pipestress/README.md),
[programs/relrofault/README.md](../programs/relrofault/README.md),
[programs/shell/README.md](../programs/shell/README.md),
[programs/stackoverflow/README.md](../programs/stackoverflow/README.md),
[programs/stdiotest/README.md](../programs/stdiotest/README.md),
[programs/terminal/README.md](../programs/terminal/README.md),
[programs/threadchurn/README.md](../programs/threadchurn/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[services/crasher/README.md](../services/crasher/README.md),
[services/pwrmgr/README.md](../services/pwrmgr/README.md),
[services/svcmgr/README.md](../services/svcmgr/README.md),
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md),
[services/svctest/README.md](../services/svctest/README.md),
[services/usertest/README.md](../services/usertest/README.md), [xtask/README.md](../xtask/README.md)
