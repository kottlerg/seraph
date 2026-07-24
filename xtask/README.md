# xtask

Build task runner for Seraph. Invoke via `cargo xtask <command>`.

---

## Commands

### `cargo xtask build`

Build Seraph components and populate `sysroot/`.

```
cargo xtask build [--arch x86_64|riscv64] [--release] [--component boot|kernel|init|all] [--debug <comp>[,...]]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--release` | off | Build in release mode |
| `--component` | `all` | Build a single component (`boot`, `kernel`, `init`, or `all`) |
| `--debug` | (none) | Emit debuginfo (`debug=2`, `opt-level=1`) for the named component(s) only, e.g. `--debug kernel,procmgr`; applies within the active profile. See [Build Profiles](../docs/build-system.md#build-profiles). |

The sysroot is architecture-specific. Building for a different arch than the
existing sysroot is an error — run `cargo xtask clean` first.

---

### `cargo xtask run`

Launch Seraph under QEMU. `run` is a pure runner — it does not build.
Run `cargo xtask build` first; `run` errors fast if the sysroot is empty
or stamped for a different architecture.

```
cargo xtask run [--arch x86_64|riscv64] [--gdb] [--headless] [--verbose] [--cpus N] [--mem MIB] [--riscv-mmu sv39|sv48|sv57]
```

| Option | Description |
|---|---|
| `--arch` | Target architecture (default: `x86_64`) |
| `--gdb` | Start QEMU with a GDB server on localhost:1234; QEMU pauses at startup. Userspace binaries are PIE with a per-spawn randomized base (ASLR, #39): take the bias from the creator's log line (procmgr `spawn image bias=0x…`, init `init: <svc> image bias=0x…`, kernel `init: PIE bias=0x…`) and load symbols with `add-symbol-file <binary> -o <bias>` |
| `--headless` | Run without a display window (`-display none`) |
| `--verbose` | Show all serial output; by default output is filtered until `[--------] boot:` appears |
| `--cpus` | Number of vCPUs to expose to the guest (default: `4`; bounded by `1..=512`, the boot-protocol `MAX_CPUS` the kernel sizes its per-CPU structures from) |
| `--mem` | Guest memory size in MiB (default: `512`) |
| `--riscv-mmu` | Guest RISC-V paging-mode ceiling (default: `sv48`; riscv64 only, ignored on x86_64). Sets the QEMU `svNN` CPU properties so the DTB `mmu-type` advertises the chosen ceiling; the kernel negotiates the highest advertised mode it supports at boot. The default pins `sv48` because QEMU ≥ 8.0 otherwise defaults the rv64 CPU to `sv57` |

**x86-64** selects an acceleration backend per host: KVM on Linux,
HVF on macOS, WHPX on Windows, NVMM on NetBSD, or TCG everywhere else
(see `SERAPH_ACCEL` below to override). KVM/HVF hosts must advertise
x86-64-v3 (AVX2/BMI2/FMA — Haswell+ / Excavator+) because the userspace
target is pinned to that psABI level; TCG mode uses
`-cpu max,migratable=no` which emulates the same baseline. Requires
OVMF firmware (`dnf install edk2-ovmf` / `apt install ovmf` /
`pacman -S edk2-ovmf` / Homebrew `brew install qemu` /
FreeBSD `pkg install edk2-qemu-x64`).

**RISC-V** always uses TCG with edk2 UEFI firmware and OpenSBI (loaded
automatically by QEMU's `virt` machine). Requires edk2 RISC-V firmware
(`dnf install edk2-riscv64` / `apt install qemu-efi-riscv64`) and
QEMU ≥ 8.0 (V extension); QEMU ≥ 9.1 unlocks the named `-cpu rva23s64`
model (currently the runner uses the explicit feature string until the
CI floor catches up).

#### Environment variables

These override `cargo xtask run`'s built-in firmware and accelerator
selection. None are required when the host follows FHS conventions
and the distro ships standard firmware packages.

| Var | Effect |
|---|---|
| `SERAPH_OVMF_CODE` | Direct path to the OVMF code firmware. Skips the per-platform default search. |
| `SERAPH_RISCV_CODE` | Direct path to `RISCV_VIRT_CODE.fd`. Must be set together with `SERAPH_RISCV_VARS` — partial overrides are rejected (a custom code image paired against the system vars template corrupts NVRAM state). |
| `SERAPH_RISCV_VARS` | Direct path to `RISCV_VIRT_VARS.fd`. See pairing rule above. |
| `SERAPH_ACCEL` | One of `auto` / `tcg` / `kvm` / `hvf` / `whpx` / `nvmm`. `auto` (the default) runs per-host detection. Cross-arch guests (e.g. riscv64 on x86) always resolve to `tcg`; an explicit non-`tcg`/`auto` override in that case emits a stderr warning. Unrecognized values also warn and fall through to detection. |

Default firmware search paths per host:

- **Linux** OVMF: `/usr/share/edk2/ovmf/OVMF_CODE.fd`, `/usr/share/OVMF/OVMF_CODE.fd`, `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd`, `/usr/share/ovmf/OVMF.fd`, `/usr/share/edk2/x64/OVMF_CODE.4m.fd`
- **Linux** RISC-V: `/usr/share/edk2/riscv`, `/usr/share/edk2-riscv`, `/usr/share/qemu-efi-riscv64`
- **macOS** (both): `/opt/homebrew/share/qemu`, `/usr/local/share/qemu`
- **BSD** (both): `/usr/local/share/qemu`, `/usr/local/share/uefi-firmware`
- **Windows / other**: no defaults; the relevant `SERAPH_*` env var is required.

---

### `cargo xtask mkdisk`

Re-mirror `rootfs/` into `sysroot/`, re-synthesise test fixtures, and
regenerate `disk.img` without invoking cargo. Use after editing
`rootfs/` to refresh the boot image without paying for a full
`cargo xtask build` (which would also run cargo fmt + clippy + check +
binary install). Requires a populated, arch-tagged sysroot from a prior
`cargo xtask build`.

The mirror is authoritative over the rootfs-managed subtrees (`config/`,
`data/`): files deleted from `rootfs/` are pruned from the sysroot, while
build-owned trees (`esp/`, `services/`, `programs/`, `tests/`) and the
synthesised `data/svctest/` fixtures are left untouched. To pack a
hand-staged sysroot that diverges from `rootfs/` — e.g. a test recipe
copied from `sysroot/config/svcmgr/tests/` into
`sysroot/config/svcmgr/services/` — use `--repack-only`, which skips the
re-mirror and packs the sysroot exactly as it stands (a plain repack would
prune the hand-added recipe).

`mkdisk` does **not** author `sysroot/EFI/seraph/bootstrap.bundle` — it
fails if the bundle is missing. The bundle is composed by
`cargo xtask build` (default-init) or by
[`cargo xtask compose-bundle`](#cargo-xtask-compose-bundle) (any
harness).

`disk.img` carries three GPT partitions: the EFI System Partition
(from `sysroot/esp/`), the arch-specific Seraph root (from `sysroot/`,
excluding `esp/` and `data/`), and an arch-neutral `SERAPH_DATA`
partition (from `sysroot/data/`). The data partition is authored
unconditionally — there is no flag to toggle it. vfsd auto-mounts it at
`/data`; the data tree lives only on this partition, not on root.
(vfsd's fall-through would also serve `/data` from a root-fs directory,
so a dedicated partition is a disk-authoring choice — the in-tree image
uses the partition.) This applies to `build`, `mkdisk`, and
`compose-bundle` alike.

```
cargo xtask mkdisk [--arch x86_64|riscv64] [--repack-only] [--no-kaslr]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture — must match the existing sysroot's arch tag |
| `--repack-only` | `false` | Skip the `rootfs/` re-mirror and pack the sysroot as it stands — preserves a hand-staged service set the authoritative mirror would otherwise reconcile |
| `--no-kaslr` | `false` | Stage the `\EFI\seraph\nokaslr` override knob so the bootloader boots the kernel at its deterministic (un-randomized) layout, for GDB / symbolization; omit to remove the knob and re-enable KASLR |

Example — stage `svctest` and run it (`--repack-only` keeps the hand-added
recipe; a plain repack would prune it):

```sh
cp sysroot/config/svcmgr/tests/svctest.svc sysroot/config/svcmgr/services/
cargo xtask mkdisk --repack-only --arch x86_64
cargo xtask run --arch x86_64
```

See [docs/testing.md](../docs/testing.md) for the test-harness gating
contract.

---

### `cargo xtask compose-bundle`

Compose `sysroot/esp/EFI/seraph/bootstrap.bundle` from canonical
binaries under `sysroot/services/` and repack `disk.img`. Symmetric
with `mkdisk`: both end with `create_disk_image`, the difference being
which file they author. `compose-bundle` is the bundle authoring step;
`mkdisk` never authors the bundle.

```
cargo xtask compose-bundle [--arch x86_64|riscv64] [--harness init|ktest]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture — must match the existing sysroot's arch tag |
| `--harness` | `init` | Which binary becomes the bundle's `init` entry: `init` for the regular userspace init, `ktest` for the kernel-test harness |

`--harness init` produces a 7-entry bundle (`init` + 6 boot modules in
the order the bootloader expects). `--harness ktest` produces a
single-entry bundle (`ktest` as the `init` entry, zero modules); ktest
is monolithic and does not spawn userspace.

Both `cargo xtask build` and `compose-bundle` are *authoring* steps —
both deliberately overwrite the bundle. `mkdisk` is the
refresh-from-sysroot path and never authors.

Example — switch to ktest, run, then switch back to regular init:

```sh
cargo xtask compose-bundle --arch x86_64 --harness ktest
cargo xtask run --arch x86_64 --headless

# Reset to default-init for the next boot:
cargo xtask compose-bundle --arch x86_64 --harness init
cargo xtask run --arch x86_64
```

ktest's runtime options (`shutdown_policy`, `timeout_secs`, filter
tiers, bench iteration count) bake in as compile-time defaults in
`core/ktest/src/cmdline.rs::KtestConfig::DEFAULT` (CI-friendly:
shutdown=Always, timeout=0, full filter, 1000 bench iters). To change
them, edit the constant and `cargo xtask build --component ktest`.

---

### `cargo xtask clean`

Remove the sysroot (and optionally `target/`).

```
cargo xtask clean [--all]
```

| Option | Description |
|---|---|
| `--all` | Also run `cargo clean` to remove the `target/` directory |

---

### `cargo xtask test`

Run Seraph unit tests on the host target.

```
cargo xtask test [--component boot|protocol|kernel|init|all]
```

Tests compile for the host — no `--arch` flag needed. The workspace-level
`panic=abort` profile does not affect the test harness.

---

### `cargo xtask run-parallel`

Launch N QEMU instances in parallel against an already-built sysroot,
classifying each run's outcome via user-supplied pass/fail regexes.
Intended for shaking out timing-dependent bugs (races, lost wakeups,
scheduling order) that single-shot `cargo xtask run` cannot reliably
expose. Requires a populated sysroot — run `cargo xtask build` first.

```
cargo xtask run-parallel \
    --arch x86_64|riscv64 \
    --parallel N \
    --runs M \
    [--timeout SECONDS] \
    [--cpus N] \
    [--mem MIB] \
    [--riscv-mmu sv39|sv48|sv57] \
    [--pass REGEX] \
    [--fail REGEX] \
    [--fail-grace-secs SECONDS] \
    [--debug-listen] \
    [--hold-on-hang]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--parallel` | (required) | Concurrency: QEMU instances in flight at once |
| `--runs` | (required) | Total runs, dispatched in waves of `--parallel` |
| `--timeout` | `30` | Per-run timeout in seconds; expired runs are SIGKILLed and classified `HANG` (unless a pass marker matched first) |
| `--cpus` | `4` | vCPUs per guest (bounded by `1..=512`, the boot-protocol `MAX_CPUS`) |
| `--mem` | `512` | Guest memory size in MiB |
| `--riscv-mmu` | `sv48` | Guest RISC-V paging-mode ceiling (riscv64 only, ignored on x86_64); same semantics as `cargo xtask run --riscv-mmu` |
| `--pass` | `ALL TESTS PASSED` | Regex marking a successful run. The default matches the cross-harness terminal marker `[<harness>] ALL TESTS PASSED` standardised in [docs/testing.md](../docs/testing.md). On match the log is discarded and the run is classified `PASS` |
| `--fail` | `SOME TESTS FAILED\|KERNEL EXCEPTION\|FATAL:\|PANIC( at \|: )\|=== WATCHDOG` | Regex marking a failed run; the **first** match wins. Matches the cross-harness terminal marker `[<harness>] SOME TESTS FAILED` ([docs/testing.md](../docs/testing.md)) plus the kernel's own death markers (`KERNEL EXCEPTION` + `FATAL:` for a hardware trap, `PANIC at`/`PANIC:` for a Rust `panic!`, `=== WATCHDOG` for a scheduler wedge-detector dump) so a crash classifies `FAIL` rather than `HANG`. The benign `USERSPACE FAULT` path matches none of these. On match the log is preserved as `FAIL-<run>.log`. Failure takes precedence over success. Override with a never-matching pattern (e.g. `'$.^'`) to disable |
| `--fail-grace-secs` | `10` | After the first `--fail` match, wait this many seconds (bounded by `--timeout`) before SIGKILL, so the trailing fault dump still lands in the log. A crashed run thus aborts ~grace seconds after the first match instead of idling to `--timeout` |
| `--debug-listen` | off | Expose each guest's gdbstub without pausing it (QEMU `-s`, tcp::1234) so a wedged guest can be attached post-hoc: `gdb -ex 'target remote :1234'`. Requires `--parallel 1` (one gdbstub port) |
| `--hold-on-hang` | off | On a hard-timeout `HANG` (no `--fail` match), do not kill QEMU: print the attach instructions and block until the instance is terminated externally, preserving the wedged guest for a debugger. Pair with `--debug-listen`. Requires `--parallel 1` |

**Mode-agnostic**: xtask does not know about ktest, svctest, or any other
rootfs configuration. Pass/fail markers come from the invoker. The default
`--pass` works for both modes because they emit the same terminal marker.
Override for other configurations:

```sh
# Default (works for ktest or svctest)
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100

# Custom marker
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100 \
    --pass 'my-app: shutdown clean' --fail 'PANIC'
```

**Output**: one line per completed run, plus a summary block. Logs for
non-passing runs are preserved under `target/xtask/run-parallel/` as
`FAIL-<run>.log`, `HANG-<run>.log`, `ERR-<run>.log`, or `QEMU-CRASH-<run>.log`.
PASS logs are discarded.

**Outcome precedence**:
1. `--fail` regex matches → `FAIL` (a live match also triggers early abort
   after `--fail-grace-secs`, bounded by `--timeout`; the verdict is unchanged)
2. `--pass` regex matches → `PASS` (even if QEMU was watchdog-killed,
   which is the normal case for kernels that idle after success)
3. Watchdog timeout → `HANG`
4. Exit code 0 with no marker → `OK`
5. Killed by SIGSEGV/SIGABRT with no marker → `QEMU-CRASH` — the host emulator
   crashed, not the guest. Tallied in the summary and preserved as
   `QEMU-CRASH-<run>.log`, but does **not** fail the run (infrastructure flake,
   not a regression in the OS under test; the recurring case is the QEMU 8.2.x
   multi-threaded-TCG segfault, [QEMU gitlab #2220](https://gitlab.com/qemu-project/qemu/-/issues/2220)).
   SIGKILL is excluded (the `--timeout` kill, or an OOM).
6. Other exit code → `ERR rc=<n>` (a signal death is reported as `128 + signum`,
   e.g. `139` for SIGSEGV)

---

### `cargo xtask test-terminal`

Boot the terminal interactive test, exercising keyboard input end-to-end
through the live virtio-input driver and the autostarted `terminal`. Launches
QEMU headless with a QMP control socket, waits for the guest to print
`terminal: READY for injection` on the serial log, injects a known key
sequence (`help`, a stray `x`, Backspace, Return) via QMP `input-send-event`,
and asserts — host-side — that the terminal's local echo, the shell's `$ `
prompt, and the relayed `help` output (`shell built-ins:`) appear on the serial
stream. Exits non-zero on an injection error or the 180 s timeout. This subsumes
the former standalone keyboard smoke test: the echoed `help` proves keysym
decode, and Return/Backspace prove the named-key decodes.

A pure runner — it neither builds nor stages. `terminal.svc` is in the default
boot set, so the terminal autostarts; just build and repack:

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test-terminal [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md) for the harness model.

---

### `cargo xtask test-vmgenid`

Boot the VMGENID snapshot-resume test (#395), x86_64 only — QEMU's riscv64
`virt` machine has no VMGENID. Boots headless with a fixed generation GUID,
waits for the kernel's `entropy: vmgenid armed` and the terminal's READY
markers, saves the guest via QMP `migrate` to a state file, quits the source,
then boots a second QEMU with a different GUID and `-incoming` restoring the
state. Asserts — host-side — the kernel's `entropy: VM generation change
detected` marker and a post-resume interactive liveness round (`help` over
QMP → `shell built-ins:` on serial). Exits non-zero on a QMP error, a failed
migration, or a per-phase 180 s timeout.

A pure runner with the same boot requirements as `test-terminal`:

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test-vmgenid [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md) for the harness model and
`core/kernel/docs/entropy.md` for the snapshot-detection design.

---

### `cargo xtask test-kaslr`

Verify KASLR (#252) on either arch. Boots the ktest bundle headless twice with
KASLR enabled, scrapes the kernel's serial-only
`kaslr: slide=… image_base=… dm_base=…` line, and asserts the joint
`(slide, dm_base)` differs between boots (joint compare + one retry bounds a
false failure at ~1e-8). Then stages the `nokaslr` knob, repacks `disk.img`,
boots once, and asserts the deterministic layout (slide 0, image at link base,
direct map at the mode floor) — always restoring the KASLR-enabled image.

A pure runner; requires the ktest bundle composed:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask compose-bundle --harness ktest [--arch x86_64|riscv64]
cargo xtask test-kaslr [--arch x86_64|riscv64] [--cpus N] [--mem MIB] [--riscv-mmu sv39|sv48|sv57]
```

See [docs/testing.md](../docs/testing.md) for the harness model and
`docs/memory-model.md` for the randomized layout.

---

## Sub-crates

| Sub-crate | Purpose |
|---|---|
| [wrapper-shim/](wrapper-shim/README.md) | Tiny native binary installed into the seraph toolchain mirror as both `rustc` and `ws-clippy`. Dispatches by argv[0] basename to exec the real rustc / clippy-driver with overlay-aware `--sysroot` flags. Built by `cargo xtask build` as part of StdUser builds; never invoked directly. |

---

## Adding a new command

1. Add a variant to `CliCommand` in `src/cli.rs` with a corresponding `Args` struct.
2. Create `src/commands/<name>.rs` with `pub fn run(ctx: &Context, args: &NameArgs) -> Result<()>`.
3. Add a match arm in `src/main.rs`.
4. Re-export the module in `src/commands/mod.rs`.

---

## Summarized By

[README.md](../README.md), [docs/build-system.md](../docs/build-system.md)
