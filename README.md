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
- [Boot Protocol ABI crate](abi/boot-protocol/) — kernel-entry contract: `BootInfo` layout, `BOOT_PROTOCOL_VERSION`, and compliant-bootloader requirements
- [System Bootstrap](docs/bootstrap.md) — end-to-end boot lifecycle summary (bootloader steps, kernel phases, init bootstrap)
- [Device Management](docs/device-management.md) — platform enumeration, devmgr, driver binding, DMA safety
- [Build System](docs/build-system.md) — toolchain, workspace layout, sysroot, xtask commands
- [Coding Standards](docs/coding-standards.md) — Rust conventions, safety contracts, documentation rules
- [Documentation Standards](docs/documentation-standards.md) — document hierarchy, authority, backlinks, required structure

Each component contains a `README.md` that references the design docs relevant to that module.
