# Seraph

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
| `abi/` | ABI-defining crates (boot-protocol, syscall) — stable cross-boundary contracts |
| `base/` | General-purpose userspace applications and utilities |
| `boot/` | UEFI bootloader |
| `devmgr/` | Device manager (platform enumeration, driver binding) |
| `docs/` | Architecture and design documentation |
| `drivers/` | Hardware device drivers (userspace, managed by devmgr) |
| `fs/` | Filesystem driver implementations (FAT, ext4, tmpfs, …; managed by vfsd) |
| `init/` | Bootstrap service — starts early services and exits |
| `kernel/` | Microkernel (scheduler, IPC, memory, capabilities) |
| `libc/` | C standard library and POSIX compatibility layer |
| `logd/` | Logging daemon — receives log messages from kernel and userspace via IPC |
| `netd/` | Network stack daemon |
| `procmgr/` | Userspace process lifecycle manager (ELF loading, creation, teardown) |
| `rootfs/` | System files installed into the sysroot during builds (boot.conf, fonts, …) |
| `ruststd/` | Rust standard library platform layer (`std::sys::seraph`) |
| `shared/` | Shared utility crates (ELF parsing, syscall wrappers) |
| `svcmgr/` | Service health monitor and restart manager |
| `targets/` | Custom Rust target JSON specs for cross-compilation |
| `vfsd/` | Virtual filesystem daemon |
| `ktest/` | In-kernel test binary, loaded in place of init for syscall and integration testing |
| `xtask/` | Build task runner (`cargo xtask`) |

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
cargo xtask run                          # build + launch under QEMU
cargo xtask run --gdb                    # pause at startup, GDB on localhost:1234
cargo xtask clean                        # remove sysroot/
cargo xtask clean --all                  # remove sysroot/ and target/
cargo xtask test                         # run all workspace tests on the host
```

`cargo xtask test` runs host-side unit tests, for all algorithmic components.
For kernel testing, set `init=ktest` in `rootfs/esp/EFI/seraph/boot.conf`, then run
`cargo xtask run`. ktest exercises every syscall through real trap/return
paths, runs cross-subsystem integration scenarios, and measures hardware
cycle counts for key operations. See [ktest/README.md](ktest/README.md) for
authoritative detail.

---

## Documentation

Overall project design documents live in [`docs/`](docs/):

- [Architecture Overview](docs/architecture.md) — component structure and design philosophy
- [Memory Model](docs/memory-model.md) — virtual address space layout, paging, allocation
- [Userspace Memory Model](docs/userspace-memory-model.md) — VA zones, heap ownership, std↔procmgr frame authority
- [IPC Design](docs/ipc-design.md) — message passing, endpoints, synchronous vs async
- [Capability Model](docs/capability-model.md) — permissions, delegation, revocation
- [Boot Protocol](docs/boot-protocol.md) — kernel-entry ABI gate: CPU/memory state and `BootInfo`
- [System Bootstrap](docs/bootstrap.md) — end-to-end boot lifecycle summary (bootloader steps, kernel phases, init bootstrap)
- [Device Management](docs/device-management.md) — platform enumeration, devmgr, driver binding, DMA safety
- [Build System](docs/build-system.md) — toolchain, workspace layout, sysroot, xtask commands
- [Coding Standards](docs/coding-standards.md) — Rust conventions, safety contracts, documentation rules
- [Documentation Standards](docs/documentation-standards.md) — document hierarchy, authority, backlinks, required structure

Each component contains a `README.md` that references the design docs relevant to that module.
