# Build System

Seraph uses Cargo as its build system. `cargo xtask` provides commands for
cross-compilation, QEMU invocation, and artifact management for x86-64 and
RISC-V from a single source tree. Kernel is soft-float on both
architectures (x86-64 baseline; RV64IMAC); userspace pins x86-64-v3 and
the RVA23U64 subset respectively.

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

The repository is a Cargo virtual workspace. Top-level directories and their
purposes are catalogued in the [root `README.md` Structure table](../README.md#structure);
this section covers only the build-relevant consequences of the layout.

Each component is a workspace member with its own `Cargo.toml`. Components
targeting different compilation targets are separate crates; types shared
between them are extracted into library crates under `abi/` (stable
cross-boundary contracts) and `shared/` (utility crates without ABI-stability
commitments).

Setting `default-members = ["xtask"]` in the workspace root `Cargo.toml` means
bare `cargo build` and `cargo run` operate only on the host-target xtask
binary. Components targeting the kernel, bootloader, or std-userspace triples
must be built via `cargo xtask build` so the correct custom target JSON and
`-Zbuild-std` flags are passed.

`abi/boot-protocol` is the source of truth for the boot protocol ABI; both
the bootloader and kernel depend on it. The kernel-entry contract the ABI
supports is in [`core/boot/docs/kernel-handoff.md`](../core/boot/docs/kernel-handoff.md).
`abi/syscall` defines syscall numbers, argument layout, and return codes; both
the kernel and userspace import it. Inline assembly that invokes syscalls
lives in `shared/syscall`.

---

## Custom Targets

The kernel cannot be compiled with standard Rust targets because it requires
specific hardware configuration: no red zone, no SSE/AVX before explicit
initialisation, and the kernel code model for higher-half placement.
Std-enabled userspace additionally needs a Seraph-OS target (`os: seraph`)
so `-Zbuild-std` selects `std::sys::seraph` rather than `std::sys::unknown`.

Custom target JSON specifications live under
[`xtask/targets/`](../xtask/targets/) — see that directory's
[`README.md`](../xtask/targets/README.md) for the file inventory and which
triple each one defines.

Key properties shared by the kernel-triple JSONs
(`x86_64-seraph-none.json`, `riscv64imac-seraph-none.json`):

- x86-64: red zone off, SSE/AVX/MMX off, soft-float, kernel code model.
- RISC-V: RV64IMAC feature set, soft-float, medium code model, lp64 ABI.
- Both: `panic-strategy: abort`, link with `rust-lld`.

The std-userspace triples (`x86_64-seraph.json`, `riscv64a23-seraph.json`)
relax the kernel-side soft-float discipline and pin a hard-microarchitecture
floor for userspace SIMD / Vector codegen:

- `x86_64-seraph.json` — **x86-64-v3** psABI feature level: SSE2/3/SSSE3/
  SSE4.1/4.2, AVX, AVX2, FMA, BMI1/2, LZCNT, MOVBE, F16C, POPCNT, plus
  XSAVE/XSAVEOPT for the lazy save/restore discipline.
- `riscv64a23-seraph.json` — **RVA23U64** userspace profile (RVA23 v1.0,
  ratified 2024-10-21): IMAFDCV plus the Zba/Zbb/Zbs bitmanip set,
  hard-float LP64D ABI. Further RVA23 mandates (Zfa, Zfhmin, Zihintntl,
  Zicond, Zimop, Zcmop, Zcb, Zvfhmin, Zvbb, Zvkt, Zkt) will land as LLVM
  and QEMU coverage broadens.

Userspace correctness under preemption is provided by lazy FP/SIMD/V
save/restore in the kernel scheduler — switch-out save on dirty, switch-in
lazy trap on first use. See `core/kernel/src/arch/{x86_64,riscv64}/fpu.rs`
for the per-arch primitives.

The x86-64 bootloader uses the built-in `x86_64-unknown-uefi` target, so no
custom JSON is needed. The RISC-V bootloader uses
`riscv64imac-seraph-uefi.json` because no equivalent built-in target exists.

Custom targets require `-Zbuild-std` (`core,alloc,compiler_builtins` for
kernel/no_std triples; `core,alloc,std,panic_abort` for std-userspace
triples) to rebuild the standard library from source. This is passed
explicitly by the build scripts rather than via `.cargo/config.toml`, to
avoid interfering with `cargo test` (which builds for the host target and
does not need `build-std`).

---

## Build Output: the Sysroot

Build artifacts are staged in `sysroot/`, which is then packaged into the
top-level `disk.img` GPT image consumed by QEMU. The sysroot is built for
one architecture at a time; the active architecture is recorded in
`sysroot/.arch`. Switching architectures requires a clean rebuild.

```
sysroot/
  .arch                   # "x86_64" or "riscv64"
  esp/                    # EFI System Partition contents
    EFI/
      BOOT/               # UEFI fallback boot path
        BOOTX64.EFI       # x86-64
        BOOTRISCV64.EFI   # RISC-V
      seraph/             # Seraph vendor directory
        boot.efi          # Bootloader (also copied to EFI/BOOT/<arch>.EFI)
        boot.conf         # Boot config (from rootfs/) — selects init mode
        kernel            # Microkernel
        init              # First userspace process
        ktest             # Kernel-validation harness
        procmgr, memmgr, devmgr, vfsd, virtio-blk
                          # Boot-loaded services (loaded directly by the
                          # bootloader as boot modules)
        fatfs             # Boot-loaded once to mount root; also lives
                          # under /bin/fatfs for VFS-loaded re-spawns
  bin/                    # Std-userspace binaries loaded by procmgr from
                          # the root partition via VFS at runtime
                          # (svcmgr, fatfs, usertest, hello, crasher,
                          # stackoverflow, pipefault, stdiotest, …)
  config/                 # System configuration (from rootfs/)
  srv/                    # Service data files (from rootfs/)
  usertest/               # Usertest data files (from rootfs/)
```

The UEFI firmware discovers the bootloader at `EFI/BOOT/BOOT<arch>.EFI`
(the UEFI specification's fallback boot path). The kernel and boot-loaded
services live alongside it under `EFI/seraph/`, the Seraph vendor directory
within the EFI partition.

Non-ESP directories (`bin/`, `config/`, `srv/`, `usertest/`) populate the
GPT image's root partition, which userspace services mount via vfsd /
fatfs after boot. The split mirrors real deployments: anything the
firmware must reach lives on the ESP; everything else lives on the root
partition.

The `esp/` and root-partition trees are populated from two sources:

- Compiled binaries are installed by `cargo xtask build` to their
  destinations (`esp/EFI/seraph/<name>` for boot modules,
  `bin/<name>` for std-userspace services, both for `fatfs`).
- Static files in [`rootfs/`](../rootfs/) are mirrored directly into
  the sysroot — every file's path under `rootfs/` is its path under
  `sysroot/` (see [`rootfs/README.md`](../rootfs/README.md)).

The disk image is assembled by xtask after the sysroot is populated. Cargo's
own `target/` directory contains intermediate compilation artifacts and is
not part of the sysroot.

---

## Convenience Commands

All build, run, clean, and test operations go through `cargo xtask`. The
authoritative command reference — every subcommand, every flag, expected
behavior — lives in [`xtask/README.md`](../xtask/README.md).

The available subcommands are `build`, `run`, `run-parallel`, `clean`, and
`test`. `build` and `run` are intentionally decoupled: `run` is a pure
runner and does not build, so a typical workflow is `cargo xtask build`
followed by `cargo xtask run` (or `cargo xtask run-parallel` for stress).

---

## QEMU and Firmware

Seraph boots via its own UEFI bootloader on both architectures. This requires
UEFI firmware in QEMU — SeaBIOS cannot load UEFI applications.

**x86-64:** Requires OVMF from `edk2-ovmf`. `cargo xtask run` searches standard
Fedora, Debian, and Arch install paths. The bootloader `.efi` reaches OVMF via
the GPT image's ESP partition, attached to the guest as a virtio-blk-pci
device.

**RISC-V:** Requires `edk2-riscv64` firmware. `cargo xtask run` searches standard
firmware paths and pads `RISCV_VIRT_CODE.fd` / `RISCV_VIRT_VARS.fd` to 32 MiB
in temporary files if necessary (QEMU virt ≥9.0 requires exactly 32 MiB).

**Minimum QEMU version:** QEMU ≥ 8.0 (V extension support) is required;
`xtask/src/qemu.rs` passes `-cpu rv64,v=true,zba=true,zbb=true,zbs=true`
for RISC-V and `-cpu max,migratable=no` on x86-64 TCG. The named
`-cpu rva23s64` model arrived in QEMU 9.1 (2024-09) and is the preferred
swap once the CI runner floor ships it; until then the explicit feature
string is the source of truth.

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
interface; invoke it with `cargo xtask <command>`.

See [`xtask/README.md`](../xtask/README.md) for the full command reference and
[`xtask/src/main.rs`](../xtask/src/main.rs) for the dispatch entry point.

---

## Summarized By

[README.md](../README.md)
