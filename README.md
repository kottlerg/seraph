# Seraph

[![build-test](https://github.com/kottlerg/seraph/actions/workflows/build-test.yml/badge.svg?branch=master)](https://github.com/kottlerg/seraph/actions/workflows/build-test.yml?query=branch%3Amaster)
[![license](https://img.shields.io/github/license/kottlerg/seraph)](LICENSE)
[![language](https://img.shields.io/github/languages/top/kottlerg/seraph)](https://www.rust-lang.org/)
[![targets](https://img.shields.io/badge/targets-x86__64%20%7C%20RISC--V-blue)](docs/architecture.md)
[![tag](https://img.shields.io/github/v/tag/kottlerg/seraph)](https://github.com/kottlerg/seraph/tags)

Seraph is a microkernel operating system written in Rust, targeting
x86-64 and RISC-V. The kernel provides only mechanism (IPC, scheduling,
memory management, and capabilities); drivers, filesystems, and services
live in userspace. Capabilities are the sole access control mechanism.
Seraph defines its own native system interfaces, not a POSIX surface
or any other OS's ABI. Userspace reaches them through standard language
runtimes (`ruststd` and `libc`).

## Goals

- Minimal, modular microkernel; most functionality in userspace
- Capability-based security model throughout
- Clear component boundaries with explicit IPC contracts
- Architecture-specific code isolated behind a shared arch-dispatch surface
- Self-hosting as a long-term goal

The framing above and these goals are summarized from [docs/architecture.md](docs/architecture.md);
see there for the authoritative statement.

## Structure

| Directory | Purpose |
|---|---|
| `abi/` | Stable cross-boundary contracts |
| `core/` | Core OS: bootloader, kernel, and the kernel-validation harness (ktest) |
| `docs/` | Architecture and design documentation |
| `programs/` | General-purpose userspace applications and utilities |
| `rootfs/` | System files installed into the sysroot during builds (config files, etc) |
| `runtime/` | Language runtime layers consumed by userspace (libc, ruststd) |
| `services/` | Userspace OS processes: managers, drivers, filesystems, daemons |
| `shared/` | Shared utility crates |
| `xtask/` | Build task runner (`cargo xtask`); custom target JSON specs under `xtask/targets/` |

## Usage

All build, run, and test operations are driven by `cargo xtask`. The full
command reference lives in [xtask/README.md](xtask/README.md); toolchain
requirements, sysroot layout, and QEMU / firmware configuration are in
[docs/build-system.md](docs/build-system.md). Common commands:

```sh
cargo xtask build                            # build (defaults: x86_64, debug)
cargo xtask build --arch riscv64             # build for RISC-V
cargo xtask build --debug kernel             # build all; debuginfo for kernel only
cargo xtask mkdisk                           # repack disk.img after rootfs/ edits
cargo xtask compose-bundle --harness ktest   # swap boot bundle to ktest harness
cargo xtask run                              # launch existing sysroot under QEMU
cargo xtask run --gdb                        # pause at start; GDB on :1234
cargo xtask test                             # run host-side workspace tests
cargo xtask clean [--all]                    # remove sysroot/ (and target/ with --all)
```

Testing spans host-side `cargo xtask test` plus in-tree QEMU harnesses
(`ktest`, `svctest`, `usertest`); the default boot is interactive and runs
no harness. See [docs/testing.md](docs/testing.md) for the full model.

---

## Documentation

Overall project design documents live in [`docs/`](docs/):

- [Architecture Overview](docs/architecture.md) — component structure and design philosophy
- [System Bootstrap](docs/bootstrap.md) — end-to-end boot lifecycle summary (bootloader
  steps, kernel phases, init bootstrap)
- [Memory Model](docs/memory-model.md) — virtual address space layout, paging, allocation
- [Userspace Memory Model](docs/userspace-memory-model.md) — three-surface VA model,
  memmgr authority, page-reservation contract
- [Process Lifecycle](docs/process-lifecycle.md) — userspace boot order,
  ProcessInfo/InitInfo handover, process-death flow
- [IPC Design](docs/ipc-design.md) — message passing, endpoints, synchronous vs async
- [Capability Model](docs/capability-model.md) — permissions, delegation, revocation
- [Fault Handling](docs/fault-handling.md) — userspace fault-handler protocol (pager):
  per-thread fault endpoint, fault taxonomy, suspend/resume/kill semantics, demand paging
- [Namespace Model](docs/namespace-model.md) — node capabilities, per-entry rights and
  visibility, walking, sandboxing as cap-distribution
- [Storage](docs/storage.md) — composition of vfsd, fs drivers, and block drivers;
  GPT role-GUID discovery; mount lifecycle
- [Device Management](docs/device-management.md) — platform enumeration, devmgr,
  driver binding, DMA safety
- [Platform Requirements](docs/platform-requirements.md) — per-arch required/opportunistic/unsupported
  CPU and platform feature baseline; boot-time feature-gate
- [Console Model](docs/console-model.md) — serial/console output ownership across boot;
  serial-driver-mediated userspace output
- [Build System](docs/build-system.md) — toolchain, workspace layout, sysroot, xtask commands
- [Coding Standards](docs/coding-standards.md) — Rust conventions, safety contracts,
  documentation rules
- [Documentation Standards](docs/documentation-standards.md) — document hierarchy,
  authority, backlinks, required structure
- [Conventions](docs/conventions.md) — versioning, backlog tracking via GitHub Issues,
  branch and PR workflow, CI gating, release production
- [Testing](docs/testing.md) — tier taxonomy, marker format, per-program tester protocol,
  sysroot layout, gating
- [Release Notes](docs/releases/README.md) — per-tag notes catalogue, naming,
  source-of-truth discipline, workflow integration

Each component contains a `README.md` that references the design docs relevant to that module.
