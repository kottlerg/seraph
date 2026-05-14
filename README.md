# Seraph

[![build-test](https://github.com/kottlerg/seraph/actions/workflows/build-test.yml/badge.svg?branch=master)](https://github.com/kottlerg/seraph/actions/workflows/build-test.yml?query=branch%3Amaster)
[![license](https://img.shields.io/github/license/kottlerg/seraph)](LICENSE)
[![language](https://img.shields.io/github/languages/top/kottlerg/seraph)](https://www.rust-lang.org/)
[![targets](https://img.shields.io/badge/targets-x86__64%20%7C%20riscv64-blue)](docs/architecture.md)
[![tag](https://img.shields.io/github/v/tag/kottlerg/seraph)](https://github.com/kottlerg/seraph/tags)

Seraph is a microkernel operating system written in Rust, targeting x86-64 and RISC-V (RV64GC).

## Goals


- Minimal, modular microkernel; most functionality in userspace
- Capability-based security model throughout
- Clear component boundaries with explicit IPC contracts
- Architecture-specific code isolated behind shared traits
- Self-hosting as a long-term goal

Summarized from the Project Goals and Philosophy sections of
[docs/architecture.md](docs/architecture.md); see there for the authoritative
statement and the reasoning behind each goal.

## Structure

| Directory | Purpose |
|---|---|
| `abi/` | Stable cross-boundary contracts |
| `base/` | General-purpose userspace applications and utilities |
| `core/` | Core OS: bootloader, kernel, and the kernel-validation harness (ktest) |
| `docs/` | Architecture and design documentation |
| `rootfs/` | System files installed into the sysroot during builds (config files, etc) |
| `runtime/` | Language runtime layers consumed by userspace (libc, ruststd) |
| `services/` | Userspace OS processes: managers, drivers, filesystems, daemons |
| `shared/` | Shared utility crates |
| `xtask/` | Build task runner (`cargo xtask`); custom target JSON specs under `xtask/targets/` |

## Usage

All build, run, and test operations are driven by `cargo xtask`. The full
command reference lives in [xtask/README.md](xtask/README.md); toolchain
requirements, sysroot layout, and QEMU / firmware configuration are in
[docs/build-system.md](docs/build-system.md). The common recipes are
summarized here for quick reference:

```sh
cargo xtask build                        # build all components (x86_64, debug)
cargo xtask build --arch riscv64         # build for RISC-V
cargo xtask build --component boot       # build a single component
cargo xtask run                          # launch the existing sysroot under QEMU (pure runner; no build)
cargo xtask run --gdb                    # pause at startup, GDB on localhost:1234
cargo xtask run-parallel --parallel 4 --runs 100   # N parallel QEMU runs for stress / race-hunting
cargo xtask clean                        # remove sysroot/
cargo xtask clean --all                  # remove sysroot/ and target/
cargo xtask test                         # run all workspace tests on the host
```

`cargo xtask test` runs host-side unit tests, for all algorithmic components.
For kernel testing, set `init=ktest` in `rootfs/esp/EFI/seraph/boot.conf`, then run
`cargo xtask run`. ktest exercises every syscall through real trap/return
paths, runs cross-subsystem integration scenarios, and measures hardware
cycle counts for key operations. See [core/ktest/README.md](core/ktest/README.md) for
authoritative detail.

---

## Documentation

Overall project design documents live in [`docs/`](docs/):

- [Architecture Overview](docs/architecture.md) — component structure and design philosophy
- [Memory Model](docs/memory-model.md) — virtual address space layout, paging, allocation
- [Userspace Memory Model](docs/userspace-memory-model.md) — three-surface VA model, memmgr authority, page-reservation contract
- [Process Lifecycle](docs/process-lifecycle.md) — userspace boot order, ProcessInfo/InitInfo handover, process-death flow
- [IPC Design](docs/ipc-design.md) — message passing, endpoints, synchronous vs async
- [Capability Model](docs/capability-model.md) — permissions, delegation, revocation
- [Namespace Model](docs/namespace-model.md) — node capabilities, per-entry rights and visibility, walking, sandboxing as cap-distribution
- [Boot Protocol ABI crate](abi/boot-protocol/) — kernel-entry contract: `BootInfo` layout, `BOOT_PROTOCOL_VERSION`, and compliant-bootloader requirements
- [System Bootstrap](docs/bootstrap.md) — end-to-end boot lifecycle summary (bootloader steps, kernel phases, init bootstrap)
- [Device Management](docs/device-management.md) — platform enumeration, devmgr, driver binding, DMA safety
- [Build System](docs/build-system.md) — toolchain, workspace layout, sysroot, xtask commands
- [Coding Standards](docs/coding-standards.md) — Rust conventions, safety contracts, documentation rules
- [Documentation Standards](docs/documentation-standards.md) — document hierarchy, authority, backlinks, required structure
- [Conventions](docs/conventions.md) — versioning, backlog tracking via GitHub Issues, branch and PR workflow, CI gating, release production
- [Release Notes](docs/releases/README.md) — per-tag notes catalogue, naming, source-of-truth discipline, workflow integration

Each component contains a `README.md` that references the design docs relevant to that module.
