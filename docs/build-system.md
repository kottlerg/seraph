# Build System

Seraph uses Cargo as its build system. `cargo xtask` provides commands for
cross-compilation, QEMU invocation, and artifact management for x86-64 and
RISC-V RV64GC from a single source tree.

---

## Toolchain

Seraph requires Rust nightly, pinned in `rust-toolchain.toml`. The following
components must be installed:

| Component | Purpose |
|---|---|
| `rust-src` | Required for `-Zbuild-std` (rebuilds `core`/`alloc` for custom targets) |
| `rustfmt` | Code formatting |
| `clippy` | Linting |
| `llvm-tools` | `llvm-objcopy`, `llvm-objdump`, symbol map utilities |

Run `rustup show` in the repository root to confirm the toolchain is active.

---

## Workspace Structure

The repository is a Cargo virtual workspace. Each component is a workspace member
with its own `Cargo.toml`. Components targeting different compilation targets are
separate crates; types shared between them are extracted into library crates.

```
Cargo.toml                    # Virtual workspace root (default-members = ["xtask"])
├── abi/
│   ├── boot-protocol/        # BootInfo types (no_std lib) — boot ABI
│   └── syscall/              # Syscall numbers, argument layout, return codes (no_std lib)
├── kernel/                   # Microkernel (no_std; custom target)
├── boot/                     # UEFI bootloader (no_std; UEFI target)
├── init/                     # Bootstrap process (no_std; kernel target)
├── shared/
│   ├── elf/                  # ELF parser (no_std lib)
│   └── syscall/              # Inline-asm syscall wrappers — userspace only (no_std lib)
└── xtask/                    # Build task runner (std; host target)
```

`abi/boot-protocol` is a `#![no_std]` library containing the `BootInfo` structure
and associated types. Both the bootloader and kernel depend on it. This crate is the
single source of truth for the boot protocol ABI; the types, layout, and
version invariants live in the crate itself at
[`abi/boot-protocol/`](../abi/boot-protocol/), and the kernel-entry
contract the ABI supports is in
[`core/boot/docs/kernel-handoff.md`](../core/boot/docs/kernel-handoff.md).

`abi/syscall` defines syscall numbers, argument layout, and return codes. It is
the single source of truth for the syscall ABI; both the kernel and userspace
import it. Inline assembly that invokes syscalls lives in `shared/syscall`.

Setting `default-members = ["xtask"]` means bare `cargo build` and `cargo run`
operate only on the host-target xtask binary. Components using custom embedded
targets must be built via `cargo xtask build`.

---

## Custom Targets

The kernel cannot be compiled with standard Rust targets because it requires
specific hardware configuration: no red zone, no SSE/AVX before explicit
initialisation, and the kernel code model for higher-half placement.

Custom target JSON specifications live in `targets/`:

| File | Architecture | Key properties |
|---|---|---|
| `x86_64-seraph-none.json` | x86-64 | Red zone off, SSE/AVX/MMX off, soft-float, kernel code model |
| `riscv64gc-seraph-none.json` | RISC-V | RV64GC features, medium code model, lp64d ABI |

Both targets set `panic-strategy: abort` and link with `rust-lld`.

The bootloader uses built-in Rust targets (`x86_64-unknown-uefi` for x86-64),
so no custom JSON is needed for it.

Custom targets require `-Zbuild-std=core,alloc,compiler_builtins` to rebuild
the standard library from source. This is passed explicitly by the build scripts
rather than via `.cargo/config.toml`, to avoid interfering with `cargo test`
(which builds for the host target and does not need `build-std`).

---

## Build Output: the Sysroot

Build artifacts are staged in `sysroot/`, which is used directly as a virtual
FAT drive by QEMU. The sysroot is built for one architecture at a time; the
active architecture is recorded in `sysroot/.arch`. Switching architectures
requires a clean rebuild.

```
sysroot/
  .arch                  # "x86_64" or "riscv64"
  efi/
    BOOT/
      BOOTX64.EFI        # UEFI fallback bootloader path (x86-64)
    seraph/
      seraph-kernel      # Kernel ELF binary
  conf/                  # (future) System configuration
  lib/                   # (future) Shared libraries
```

The UEFI firmware (OVMF) discovers the bootloader at `EFI/BOOT/BOOTX64.EFI`
(the UEFI specification's fallback boot path). The kernel lives alongside it
under `EFI/seraph/`, the Seraph vendor directory within the EFI partition. This
arrangement mirrors real deployments: when the system eventually has a separate
EFI System Partition and additional mounted filesystems, both the bootloader and
the kernel remain on the ESP where the firmware can reach them.

No temporary copies or image construction steps are needed — `cargo xtask run`
passes the sysroot directory directly to QEMU's `fat:rw:` drive parameter.

Cargo's own `target/` directory contains intermediate compilation artifacts and
is not part of the sysroot.

---

## Convenience Commands

All build, run, clean, and test operations go through `cargo xtask`. See
[`xtask/README.md`](../xtask/README.md) for the full command reference.

| Command | Purpose |
|---|---|
| `cargo xtask build` | Build components and populate the sysroot |
| `cargo xtask clean` | Remove the sysroot (and optionally `target/`) |
| `cargo xtask run` | Build (incremental) and launch under QEMU |
| `cargo xtask test` | Run workspace unit tests on the host |

---

## QEMU and Firmware

Seraph boots via its own UEFI bootloader on both architectures. This requires
UEFI firmware in QEMU — SeaBIOS cannot load UEFI applications.

**x86-64:** Requires OVMF from `edk2-ovmf`. `cargo xtask run` searches standard
Fedora, Debian, and Arch install paths. The bootloader `.efi` is exposed to QEMU
via a virtual FAT image (QEMU's `fat:rw:DIR` syntax), which OVMF reads like a
real FAT partition.

**RISC-V:** Requires `edk2-riscv64` firmware. `cargo xtask run` searches standard
firmware paths and pads `RISCV_VIRT_CODE.fd` / `RISCV_VIRT_VARS.fd` to 32 MiB
in temporary files if necessary (QEMU virt ≥9.0 requires exactly 32 MiB).

---

## Testing

### Kernel Testing Strategy

**Host unit tests** — Pure algorithmic modules (buddy allocator, slab allocator, capability
tree, scheduler run queues) keep hardware dependencies behind trait boundaries. The kernel's
`lib` target uses `#![cfg_attr(not(test), no_std)]`, allowing `cargo test -p seraph-kernel`
to run these modules on the host under the standard test harness.

**QEMU integration tests** — Code requiring real hardware (page tables, interrupts, context
switching) is tested under QEMU with a custom harness that runs tests sequentially and reports
results over serial. This harness will be implemented when arch code is written.

### Running Tests

```sh
cargo xtask test                        # all workspace tests
cargo xtask test --component kernel     # single crate
```

For test naming conventions and requirements (what must be tested, what should not), see
[coding-standards.md](coding-standards.md#testing).

---

## xtask

`xtask/` is a Rust binary crate that runs on the host. It is the primary build
interface — `build.sh`, `clean.sh`, `run.sh`, and `test.sh` have been replaced.
Invoke it with `cargo xtask <command>`.

See [`xtask/README.md`](../xtask/README.md) for the full command reference and
[`xtask/src/main.rs`](../xtask/src/main.rs) for the dispatch entry point.

---

## Summarized By

[README.md](../README.md)
