# seraph-wrapper-shim

Tiny native binary installed into the seraph toolchain mirror at
`target/seraph-toolchain/bin/` as both `rustc` and `ws-clippy`, dispatching on
argv[0] basename to exec the real rustc or clippy-driver with the flags
`-Z build-std` needs to read the overlaid `std::sys::seraph`.

---

## Why

Replaces the previous `#!/bin/sh` heredoc wrappers that xtask wrote in
earlier versions of `rust_src.rs`. A native binary works on every host
with a normal executable format — no shebang interpretation, no POSIX
shell, no Unix execute-bit semantics. The shim is the last piece of the
toolchain-mirror assembly that ran into Windows portability issues; this
crate eliminates them.

## Scope

This crate exists exclusively to back the toolchain mirror. It is not a
user-facing tool. The user never invokes it directly; xtask builds it,
copies it, and arranges for cargo to spawn it as part of StdUser builds.
See [xtask/src/rust_src.rs](../src/rust_src.rs) for the install
mechanism and [xtask/README.md](../README.md) for how the toolchain
mirror fits into the wider build flow.

## Source Layout

```
wrapper-shim/
├── Cargo.toml      Dep-less host-target binary package.
├── README.md       This file.
└── src/
    └── main.rs     argv[0]-dispatched shim: rustc or ws-clippy mode.
```

## Behavior

Dispatch is by argv[0] basename:

| Install name | Behavior |
|---|---|
| `rustc`     | Exec the real rustc with `--sysroot=<mirror>` prepended, unless the caller already supplied `--sysroot`. Lets cargo's internal invocations pick up the overlay while letting an explicit `rustc --sysroot=…` caller bypass. |
| `ws-clippy` | Cargo invokes `RUSTC_WORKSPACE_WRAPPER` as `<wrapper> <rustc_path> <args...>`. Drop the cargo-prepended `<rustc_path>`, set `SYSROOT=<mirror>` in the env, and re-drive clippy-driver with `<mirror>/bin/rustc` and an explicit `--sysroot=<mirror>` arg. clippy-driver bakes its rustup env vars at compile time, so both the env and the flag are required to override its baked-in sysroot view. |

Unknown install names produce a clear error and exit 2.

On Unix the shim uses `exec(3)`
(`std::os::unix::process::CommandExt::exec`) to replace the current
process — no extra hop, no second wait. On Windows it spawns and
mirrors the child's exit code.

## Configuration

Three env vars set by xtask before invoking cargo:

| Env var | Purpose |
|---|---|
| `SERAPH_SHIM_REAL_RUSTC`     | Absolute path to the real rustup rustc binary. |
| `SERAPH_SHIM_REAL_CLIPPY`    | Absolute path to the real rustup clippy-driver binary. |
| `SERAPH_SHIM_MIRROR_SYSROOT` | Absolute path to the seraph toolchain mirror root. |

xtask is always the root of the process tree for StdUser builds, so
these env vars propagate naturally to every cargo and rustc spawn that
descends from it. Any of the three being unset (or empty) causes the
shim to die with a clear message naming the missing var.

The values are wired into a single cargo `Command` by
[`SeraphToolchain::apply_env`](../src/rust_src.rs); callers route
through that helper rather than setting any of these vars directly.

## Dependencies

Intentionally zero. The shim is on the hot path of every rustc
invocation during StdUser builds; keeping the working set tiny (roughly
std plus the few syscall sites the dispatch needs) means a release
build is around 400 KiB with no transitive crates.

## Build and Install

Built by xtask, not invoked directly:

```sh
# Triggered automatically as part of any StdUser build:
cargo xtask build

# Direct build (for inspection or debugging):
cargo build --release -p seraph-wrapper-shim
```

The release binary lands at `target/release/seraph-wrapper-shim` (with
`.exe` on Windows). xtask copies it into
`target/seraph-toolchain/bin/rustc` and
`target/seraph-toolchain/bin/ws-clippy` (same physical file, two
install names, dispatch by argv[0] basename).

## Relevant Design Documents

| Document | Why |
|---|---|
| [docs/build-system.md](../../docs/build-system.md) | System-wide build flow and toolchain conventions. |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Style and safety rules this crate follows. |
| [xtask/README.md](../README.md) | Build task runner; owns the install mechanism for this crate's binary. |

---

## Summarized By

[xtask/README.md](../README.md)
