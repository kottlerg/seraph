# xtask

Build task runner for Seraph. Invoke via `cargo xtask <command>`.

---

## Commands

### `cargo xtask build`

Build Seraph components and populate `sysroot/`.

```
cargo xtask build [--arch x86_64|riscv64] [--release] [--component boot|kernel|init|all]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--release` | off | Build in release mode |
| `--component` | `all` | Build a single component (`boot`, `kernel`, `init`, or `all`) |

The sysroot is architecture-specific. Building for a different arch than the
existing sysroot is an error — run `cargo xtask clean` first.

---

### `cargo xtask run`

Launch Seraph under QEMU. `run` is a pure runner — it does not build.
Run `cargo xtask build` first; `run` errors fast if the sysroot is empty
or stamped for a different architecture.

```
cargo xtask run [--arch x86_64|riscv64] [--gdb] [--headless] [--verbose] [--cpus N]
```

| Option | Description |
|---|---|
| `--arch` | Target architecture (default: `x86_64`) |
| `--gdb` | Start QEMU with a GDB server on localhost:1234; QEMU pauses at startup |
| `--headless` | Run without a display window (`-display none`) |
| `--verbose` | Show all serial output; by default output is filtered until `[--------] boot:` appears |
| `--cpus` | Number of vCPUs to expose to the guest (default: `4`) |

**x86-64** uses KVM acceleration when `/dev/kvm` is present, falling back
to multi-threaded TCG with `-cpu max,migratable=no`. KVM hosts must
advertise x86-64-v3 (AVX2/BMI2/FMA — Haswell+ / Excavator+) because the
userspace target is pinned to that psABI level. Requires OVMF firmware
(`dnf install edk2-ovmf` / `apt install ovmf`).

**RISC-V** uses TCG emulation with edk2 UEFI firmware and OpenSBI (loaded
automatically by QEMU's `virt` machine). Requires edk2 RISC-V firmware
(`dnf install edk2-riscv64` / `apt install qemu-efi-riscv64`) and
QEMU ≥ 8.0 (V extension); QEMU ≥ 9.1 unlocks the named `-cpu rva23s64`
model (currently the runner uses the explicit feature string until the
CI floor catches up).

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
    [--pass REGEX] \
    [--fail REGEX]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--parallel` | (required) | Concurrency: QEMU instances in flight at once |
| `--runs` | (required) | Total runs, dispatched in waves of `--parallel` |
| `--timeout` | `30` | Per-run timeout in seconds; expired runs are SIGKILLed and classified `HANG` (unless a pass marker matched first) |
| `--cpus` | `4` | vCPUs per guest |
| `--pass` | `ALL TESTS PASSED` | Regex marking a successful run. The default matches the unique terminal marker emitted by both ktest (`ktest: ALL TESTS PASSED`) and usertest (`[usertest] ALL TESTS PASSED`). On match the log is discarded and the run is classified `PASS` |
| `--fail` | (none) | Regex marking a failed run; the **first** match wins. On match the log is preserved as `FAIL-<run>.log`. Failure takes precedence over success |

**Mode-agnostic**: xtask does not know about ktest, usertest, or any other
rootfs configuration. Pass/fail markers come from the invoker. The default
`--pass` works for both modes because they emit the same terminal marker.
Override for other configurations:

```sh
# Default (works for ktest or usertest)
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100

# Custom marker
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100 \
    --pass 'my-app: shutdown clean' --fail 'PANIC'
```

**Output**: one line per completed run, plus a summary block. Logs for
non-passing runs are preserved under `target/xtask/run-parallel/` as
`FAIL-<run>.log`, `HANG-<run>.log`, or `ERR-<run>.log`. PASS logs are
discarded.

**Outcome precedence**:
1. `--fail` regex matches → `FAIL`
2. `--pass` regex matches → `PASS` (even if QEMU was watchdog-killed,
   which is the normal case for kernels that idle after success)
3. Watchdog timeout → `HANG`
4. Exit code 0 with no marker → `OK`
5. Other exit code → `ERR rc=<n>`

---

## Adding a new command

1. Add a variant to `CliCommand` in `src/cli.rs` with a corresponding `Args` struct.
2. Create `src/commands/<name>.rs` with `pub fn run(ctx: &Context, args: &NameArgs) -> Result<()>`.
3. Add a match arm in `src/main.rs`.
4. Re-export the module in `src/commands/mod.rs`.

---

## Summarized By

[README.md](../README.md), [docs/build-system.md](../docs/build-system.md)
