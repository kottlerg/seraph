# Build System

Seraph uses Cargo as its build system. `cargo xtask` provides commands for
cross-compilation, QEMU invocation, and artifact management for x86-64 and
RISC-V from a single source tree. Kernel is soft-float on both
architectures (x86-64 baseline; RV64IMAC); std-userspace pins x86-64-v3 and
the RVA23U64 subset respectively; low-level userspace (init, ktest, memmgr)
keeps the kernel's soft-float baseline.

---

## Toolchain

Seraph requires Rust nightly, pinned in `rust-toolchain.toml`. The following
components must be installed:

| Component | Purpose |
|---|---|
| `rust-src` | Required for `-Zbuild-std` (rebuilds `core`/`alloc`, and `std` for std-userspace triples, from source) and the overlaid `std::sys::seraph` mirror |
| `rustfmt` | Code formatting |
| `clippy` | Linting |
| `llvm-tools` | `llvm-objcopy`, `llvm-objdump`, symbol map utilities |

Run `rustup show` in the repository root to confirm the toolchain is active.

xtask reads ELF, PE and DWARF with the `object`, `addr2line` and `rustc_demangle` crates the
toolchain's sysroot ships for std's backtraces
([coding-standards.md](coding-standards.md#dependencies) § Dependencies). The std of every host
carries them, with `object`'s ELF and PE readers (on macOS too), except two: a
`*-pc-windows-msvc` host's, which symbolizes its backtraces through the platform's debug-help
library instead, and an AIX host's, whose `object` reads XCOFF only. On Windows xtask therefore
needs the GNU host toolchain (`rustup set default-host x86_64-pc-windows-gnu` before the pinned
toolchain is installed); on a `*-windows-msvc` host it fails to compile, naming that toolchain.
xtask calls the host's C library through bindings declared in `xtask/src/sys.rs`, which hold its
values for Linux, macOS, FreeBSD, DragonFly BSD, NetBSD, OpenBSD, illumos and Solaris; on any
other Unix xtask fails to compile, naming that file.

`cargo xtask test` runs the host tests a second time built for `riscv64gc-unknown-linux-gnu`,
under QEMU's user-mode emulator, so it needs a Linux host with three more packages: the emulator
(`qemu-riscv64`), the riscv64 Linux cross compiler that links the test binaries
(`riscv64-linux-gnu-gcc`), and its C library under `/usr/riscv64-linux-gnu`. On Debian and Ubuntu
they are `qemu-user`, `gcc-riscv64-linux-gnu` and `libc6-dev-riscv64-cross`; on Arch,
`qemu-user`, `riscv64-linux-gnu-gcc` and `riscv64-linux-gnu-glibc`. The command fails, naming
them, when one is missing.

`cargo xtask symbolize` reads DWARF and symbol tables in Rust, with the `addr2line` and `object`
crates the toolchain's sysroot ships ([coding-standards.md](coding-standards.md#dependencies)
§ Dependencies), so symbolizing needs no host tool beyond the toolchain. Debugging a guest
through QEMU's gdbstub ([testing.md § Troubleshooting](testing.md#troubleshooting)) needs a host
GDB that supports the guest's architecture: a riscv64 guest needs a GDB built for RISC-V as well
as the host, such as one configured with `--enable-targets=all` or a distribution's multi-target
package (`gdb-multiarch` on Debian and Ubuntu). `gdb -batch -ex 'set architecture riscv:rv64'`
fails on a GDB without it.

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
`-Zbuild-std` flags are passed and, for the bootloader and each kernel,
`RUSTFLAGS` is set (§ Custom Targets).

[`abi/boot-protocol`](../abi/boot-protocol/README.md) is the source of truth for the boot
protocol ABI; both the bootloader and kernel depend on it. The kernel-entry contract the
ABI supports is in [`core/boot/docs/kernel-handoff.md`](../core/boot/docs/kernel-handoff.md).
[`abi/syscall`](../abi/syscall/README.md) defines syscall numbers, argument layout, and
return codes; both the kernel and userspace import it. Inline assembly that invokes
syscalls lives in [`shared/syscall`](../shared/syscall/README.md).

---

## Custom Targets

The kernel cannot be compiled with standard Rust targets because it requires
specific hardware configuration: no red zone, no SSE/AVX/MMX codegen
(soft-float throughout), and a static-PIE image the bootloader relocates into
the higher half.
Std-enabled userspace additionally needs a Seraph-OS target (`os: seraph`)
so `-Zbuild-std` selects `std::sys::seraph` rather than `std::sys::unknown`.

Custom target JSON specifications live under
[`xtask/targets/`](../xtask/targets/) — see that directory's
[`README.md`](../xtask/targets/README.md) for the file inventory and which
triple each one defines.

Key properties shared by the kernel-triple JSONs
(`x86_64-seraph-none.json`, `riscv64imac-seraph-none.json`):

- x86-64: red zone off, SSE/AVX/MMX off, soft-float, small code model.
- RISC-V: RV64IMAC plus Svinval/Svpbmt/Svnapot, soft-float, medium code model, lp64 ABI.
- Both: `panic-strategy: abort`, `relocation-model: pic`, `-pie
  --no-dynamic-linker -Bsymbolic -z max-page-size=4096` link args, link
  with `rust-lld`. Inline stack probes (`"stack-probes": {"kind": "inline"}`):
  on x86-64 a frame larger than one page touches each page in turn and faults
  on a kernel stack's guard page instead of stepping over it. On riscv64 a
  `call` writes nothing to the stack and a split prologue leaves up to 6120
  bytes below its return-address save unwritten (the rest of its first,
  2032-byte adjustment and up to a page of the second, which no probe
  touches), so the guard rests instead on the kernel frame bound: the
  riscv64 kernel builds with `-Z emit-stack-sizes`, and `cargo xtask build`
  fails when a function of the image has a frame above 2032 bytes
  ([coding-standards.md](coding-standards.md) § Kernel Stack Frames;
  [core/kernel/docs/memory-internals.md](../core/kernel/docs/memory-internals.md)
  § Kernel Stack Guards). The kernel is a static-PIE (`ET_DYN`) image; the
  bootloader chooses its load bias (KASLR, #252) and applies its
  `RELATIVE` relocations before handoff.

The low-level-userspace triples (`x86_64-seraph-lowuser.json`,
`riscv64imac-seraph-lowuser.json` — init, ktest, memmgr) share the same
PIE treatment as the kernel triples (the kernel dropped x86-64's kernel
code model to `small` when it went PIE): `relocation-model: pic`, the
same `-pie …` link args, producing `ET_DYN` images with `RELATIVE`-only
relocations that loaders place at a randomized base and whose
`PT_GNU_RELRO` region they seal read-only after relocation (ASLR, #39).
They emit inline stack probes (`"stack-probes": {"kind": "inline"}`) as the
other triples do, and every stack of their binaries keeps a guard of
`process_abi::STACK_GUARD_PAGES` (four) pages: init's main stack, which the
kernel places, init's log-thread stack, memmgr's main stack, which init
places through `shared/process-layout`, and ktest's child stacks. On riscv64 a
`call` writes nothing to the stack and a split prologue leaves up to 6120
bytes below its return-address save unwritten, and with no vector extension
a callee's first store lies at most a page below its entry, so two
consecutive stack stores lie at most 10216 bytes apart; ktest's
`integration::child_stack_guard` checks that an overflowing frame faults in
a child stack's guard.

The std-userspace triples (`x86_64-seraph.json`, `riscv64a23-seraph.json`)
carry the same PIE treatment (plus `tls-model: local-exec`, keeping TLS
access GOT-free so no non-`RELATIVE` relocations appear), emit inline
stack probes (`"stack-probes": {"kind": "inline"}`, so a frame larger than one page
touches its pages in turn and faults on a thread stack's guard
instead of skipping it), relax the kernel-side soft-float discipline,
and pin a hard-microarchitecture floor for userspace SIMD / Vector
codegen. On riscv64 a `call` writes nothing to the stack, a split prologue
leaves up to 6120 bytes below its return-address save unwritten (the rest of
its first, 2032-byte adjustment and its second adjustment of up to a page,
which no probe touches), and the probe of a vector frame lies a page below
its fixed area, so two consecutive stack stores can lie up to 14312 bytes
apart. Every main-thread stack that `shared/process-layout` places and every
thread stack std spawns therefore keeps a guard of four pages
(`process_abi::STACK_GUARD_PAGES`; [`threadstack`](../programs/threadstack/README.md)'s
`splitframe` and `span` modes check it), where x86-64, whose `call` pushes
the return address, needs one. The two floors:

- `x86_64-seraph.json` — **x86-64-v3** psABI feature level: SSE2/3/SSSE3/
  SSE4.1/4.2, AVX, AVX2, FMA, BMI1/2, LZCNT, MOVBE, F16C, POPCNT, CX16, LAHF/SAHF,
  plus XSAVE/XSAVEOPT for the eager-save / lazy-restore discipline.
- `riscv64a23-seraph.json` — a subset of the **RVA23U64** userspace profile (RVA23 v1.0,
  ratified 2024-10-21): IMAFDCV plus the Zba/Zbb/Zbs bitmanip set,
  hard-float LP64D ABI.

These JSONs pin the *instruction baseline* (the psABI feature level the toolchain emits). The
*runtime platform / silicon-era contract* — which CPU and platform features the kernel requires,
uses opportunistically, or does not support, and the boot-time feature-gate that enforces it — is in
[platform-requirements.md](platform-requirements.md).

Userspace correctness under preemption is provided by eager FP/SIMD/V save
on switch-out and lazy restore on first FP/V use after switch-in (`#NM`
trap on x86-64, illegal-instruction trap on RISC-V). The switch-out save discipline is
specified in [scheduling-internals.md](../core/kernel/docs/scheduling-internals.md#ipi-taxonomy);
the per-arch primitives are in `core/kernel/src/arch/{x86_64,riscv64}/fpu.rs`.

The x86-64 bootloader uses the built-in `x86_64-unknown-uefi` target, so no
custom JSON is needed. The RISC-V bootloader uses
`riscv64imac-seraph-uefi.json` because no equivalent built-in target exists.
Its linker script, `core/boot/linker/riscv64-uefi.ld`, is passed by
`core/boot/build.rs` as an absolute `-T` link argument, the way
`core/kernel/build.rs` passes the kernel's, and `cargo xtask build` sets
`RUSTFLAGS` for the bootloader build to `-Zunstable-options` on both architectures.
Cargo reads the `.cargo/config.toml` of the current directory and of every
parent directory and joins their `rustflags` arrays, so a checkout nested
under another (a worktree under `.claude/worktrees/`) receives a flag once
for each config file that lists it; `RUSTFLAGS` is used in place of them
all, and a build-script link arg is emitted once, so the bootloader link is
the same from any checkout.

The riscv64 kernel build, and its Clippy pass, also run with `RUSTFLAGS` set,
to `-Zunstable-options -Zemit-stack-sizes` (`RISCV64_KERNEL_RUSTFLAGS` in
`xtask/src/commands/build.rs`), so that `-Z emit-stack-sizes` reaches the
`-Z build-std` crates as well. The x86-64 kernel build and its Clippy pass run
with `RUSTFLAGS` set to `-Zunstable-options -Zretpoline-external-thunk`
(`X86_64_KERNEL_RUSTFLAGS`), so that every indirect call and jump of the kernel
and of its `-Z build-std` crates goes through the kernel's retpoline thunk
([transient-execution.md](../core/kernel/docs/transient-execution.md)
§ Controls). `RUSTFLAGS` replaces the `[build] rustflags` of
`.cargo/config.toml` there too: a flag added to that array reaches a kernel
only when it is added to `RISCV64_KERNEL_RUSTFLAGS` and
`X86_64_KERNEL_RUSTFLAGS` as well, and a `RUSTFLAGS` set in the calling
environment does not reach the bootloader or either kernel. A
`SERAPH_FORCE_RETURN_MITIGATION` set there does reach the x86-64 kernel's
compile, which reads it to force the inputs of its return mitigations
([transient-execution.md](../core/kernel/docs/transient-execution.md)
§ Forced return mitigations); the riscv64 kernel does not read it.

Every custom triple links with `--build-id=sha1` among its `pre-link-args`, so
every ELF image the build links carries a GNU build-id note
(`.note.gnu.build-id`), the key of its symbols in the symbols store
(§ Symbols Store below). The kernel's linker scripts and `riscv64-uefi.ld`
discard every other `.note.*` section, so each places this one explicitly
ahead of its `/DISCARD/`: the kernel's in its read-only span, the riscv64
bootloader's in the data region its flat binary holds. The x86-64 bootloader,
a PE image the built-in target links, carries in its place the `CodeView`
record lld-link writes, which names its PDB by GUID and age.

Custom targets require `-Zbuild-std` (`core,alloc,compiler_builtins` for
kernel/no_std triples; `core,alloc,std,panic_abort` for std-userspace
triples) to rebuild the standard library from source. `cargo xtask build`
passes the flag explicitly.

By default `os: seraph` is not in rustc's recognised-OS list, so upstream
`std`'s build script would mark the crate `restricted_std`-gated. Because
Seraph ships a complete `std::sys::seraph` backend, the build pipeline
overlays std's `build.rs` to list `seraph` alongside the other recognised
std targets (`hermit`, `redox`, …). `std` is therefore built as a normal
stable crate, and std-userspace bins need no `#![feature(restricted_std)]`
opt-in.

---

## Build Profiles

Two Cargo profiles are defined at the workspace root (`Cargo.toml`): `dev`
(the default) and `release` (selected by `--release`). Both share
`opt-level = 2` and `debug = 0`; they differ only in two key pairs:

| Concern | `dev` | `release` |
|---|---|---|
| Iterate (runtime checks) | `debug-assertions`, `overflow-checks` on | off |
| Ship (codegen) | — | `lto = true`, `codegen-units = 1` |

Both set `panic = "abort"`. LTO has no per-package form, which is the only
reason two profiles persist rather than one. Cargo names the profiles `dev`
and `release` but writes their output to `target/<triple>/debug/` and
`target/<triple>/release/`; the CI cells and branch-protection status checks
use the directory names `debug`/`release`.

`cargo xtask build` runs every cargo command with `CARGO_INCREMENTAL=0`, the
value the Rust cache action of CI's jobs writes to their environment
(Continuous Integration below). Incremental compilation, which Cargo enables by
default for `dev`, partitions a crate's codegen units differently, and so
orders a binary's statics differently; with it off, a local `dev` build of a
commit orders its statics as CI's build of that commit does. Their addresses
can still differ from CI's by the length of the toolchain paths in panic
locations ([testing.md](testing.md#troubleshooting) § Troubleshooting). A
`CARGO_INCREMENTAL` set in the caller's environment is overridden, so a local
build never departs from CI's on this setting. `release` builds no crate
incrementally either way.

### Debuginfo is opt-in

`debug = 0` means a plain `cargo xtask build` (or `--release`) emits no
per-binary DWARF: the link output of every binary carries a symbol table and no
debug information. The build installs every image but the kernel and the
bootloader stripped of its symbol table, and keeps the link output in the
symbols store, where GDB and the symbolizers read it (§ Symbols Store below).
To debug specific components, opt them in:

```
cargo xtask build --debug <component>[,<component>…]
```

This injects `--config profile.<active>.package."<pkg>".debug=2` plus
`opt-level=1` for the named package(s) only, leaving every other binary
without debuginfo. `<active>` is `dev` by default, `release` under `--release`.
The DWARF of a named component reaches its store file; its installed image,
unless it is the kernel's, carries none.
The debugged crate drops to `opt-level = 1` (not `0`): opt-0 inflates stack
frames and risks overflowing the tight kernel/thread stacks.

Limits: under `--release`, fat LTO reoptimizes at the profile opt-level and
partially overrides the per-package `opt-level=1`, so step fidelity is
degraded — the normal debug flow uses the default (`dev`) profile.

---

## Build Output: the Sysroot

Build artifacts are staged in `sysroot/`, which is then packaged into the
top-level `disk.img` GPT image consumed by QEMU (with the data partition on a
second image, `disk-data.img`, under `mkdisk --split-data`). The sysroot is built for
one architecture at a time; the active architecture is recorded in
`sysroot/.arch`. Switching architectures requires a clean rebuild. The harness
whose bundle every pack composes, `init` or `ktest`, is recorded in
`sysroot/.harness`: `cargo xtask build` records `init`, and
`cargo xtask compose-bundle` the harness it is given.

```
sysroot/
  .arch                   # "x86_64" or "riscv64"
  .harness                # "init" or "ktest": the bundle every pack composes
  boot/                   # The installed kernel and bootloader
    kernel                # Microkernel, signed here
    boot.efi              # Bootloader, embedding the trust store
  esp/                    # EFI System Partition contents, composed by
                          # every pack from installed files
    EFI/
      BOOT/               # UEFI fallback boot path
        BOOTX64.EFI       # x86-64: a copy of boot/boot.efi
        BOOTRISCV64.EFI   # RISC-V: a copy of boot/boot.efi
      seraph/             # Seraph vendor directory
        boot.efi          # A copy of boot/boot.efi
        kernel            # A copy of boot/kernel
        bootstrap.bundle  # The recorded harness's bundle, per
                          # `abi/boot-protocol::bundle`: the installed
                          # files its list in config/bundle/ names.
                          # Exactly one of {init, ktest} appears as the
                          # bundle's `init` entry; ktest is monolithic
                          # so its bundle has zero module entries.
  services/               # Long-running userspace components sourced
                          # from services/ in the repo tree (init,
                          # procmgr, memmgr, devmgr, vfsd, svcmgr, logd,
                          # pwrmgr, timed, entropyd).
  services/drivers/       # Device drivers sourced from
                          # services/drivers/<x>/ (the
                          # InstallDest::ServicesDrivers entries in
                          # xtask/src/commands/build.rs SPECS; per-arch
                          # RTC drivers install only on their arch).
                          # Grouped to anticipate per-spawner namespace
                          # attenuation.
  services/fs/            # Filesystem drivers sourced from
                          # services/fs/<x>/ (fatfs today). VFS-loaded
                          # respawns walk /services/fs/<name>.
  programs/               # Userspace utilities and test programs sourced
                          # from programs/ in the repo tree (the
                          # InstallDest::Programs entries in
                          # xtask/src/commands/build.rs SPECS).
                          # Loaded by procmgr from the root
                          # partition via VFS at runtime.
  tests/                  # Test harnesses, per-program testers, and
                          # harness-only fixtures: kernel-surface
                          # harness (ktest), services-surface (svctest),
                          # programs-surface orchestrator (usertest),
                          # and the crasher restart-path fixture. Some
                          # test-only artifacts install outside it.
  tests/drivers/          # Test-only drivers devmgr binds only on demand
                          # (test-fault; the InstallDest::TestsDrivers
                          # entries in xtask/src/commands/build.rs SPECS),
                          # which no drivers-directory pass at boot reads.
  tests/programs/         # Per-program tester binaries discovered by
                          # the usertest orchestrator.
  config/                 # System configuration (from rootfs/), the
                          # bundle lists in config/bundle/ among it
  data/                   # Data files used by fs / namespace tests
                          # (from rootfs/), plus deterministic svctest
                          # fixtures synthesised under data/svctest/,
                          # which svctest also uses as scratch space.
  crash/                  # Created empty: the directory crashd writes
                          # cores to (services/crashd/docs/core-format.md).
```

The UEFI firmware discovers the bootloader at `EFI/BOOT/BOOT<arch>.EFI`
(the UEFI specification's fallback boot path). The kernel and the bundle of
boot-loaded services live alongside it under `EFI/seraph/`, the Seraph vendor
directory within the EFI partition.

`tests/` holds the test harnesses, per-program testers, and harness-only
fixtures, but test-only artifacts also install under `services/drivers/`,
`programs/`, `config/svcmgr/tests/`, `config/devmgr/tests/`, and `data/`;
[testing.md § Sysroot layout](testing.md#sysroot-layout) lists them.

Non-ESP, non-`data` directories (`boot/`, `services/`, `programs/`, `tests/`,
`config/`, `crash/`) populate the GPT image's root partition, which userspace
services mount via vfsd / fatfs after boot. `data/` populates a
dedicated `SERAPH_DATA` partition instead of the root partition; vfsd
auto-mounts it at `/data`. (vfsd would also serve `/data` from a root-fs
directory via fall-through, so carrying it on its own partition is a
disk-authoring choice — see [storage.md](storage.md); the in-tree image
uses the partition.) The split mirrors real deployments: anything the
firmware must reach lives on the ESP; everything else lives on the root
partition, except the discoverable `/data` mountpoint.

The ESP is derived from the root partition ([boot-media.md](boot-media.md)): every object on it,
the bootloader and the kernel included, is a byte copy of a file installed on the root partition,
and composing it copies files, signs nothing and reads no key. Every pack composes it as its last
step before it writes the images, so the ESP of every image equals the installed files. The
bundle's entries are the installed files that the recorded harness's bundle list names
(`config/bundle/<harness>.<arch>.list` where the architectures differ, `<harness>.list` where
they do not, from [`rootfs/config/bundle/`](../rootfs/config/bundle/)), each by its install path;
the list's `init` line names the object of the `init` slot. The data files a list names, the
log-level configuration and the platform description tables, the build installs under `/config/`
from the repository (`xtask/src/sysroot.rs`, `data_files`).

The `esp/` and root-partition trees are populated from two sources:

- Compiled binaries are installed by `cargo xtask build` to their
  destinations (`boot/kernel` for the kernel and `boot/boot.efi` for the
  bootloader, which reach the ESP as copies; boot modules reach the ESP only
  inside `bootstrap.bundle`),
  `services/<name>`, `services/drivers/<name>`,
  `services/fs/<name>`, or `programs/<name>` for std-userspace
  binaries, `tests/<name>` or `tests/programs/<name>` for harness
  binaries and per-program testers, `tests/drivers/<name>` for the
  test-only drivers bound on demand).
- Static files in [`rootfs/`](../rootfs/) are mirrored directly into
  the sysroot — every file's path under `rootfs/` is its path under
  `sysroot/`. The mirror is authoritative over the subtrees it owns
  (`config/`, `data/`): files deleted from `rootfs/` are pruned from the
  sysroot on the next build, while the installed binaries above and the
  synthesised `data/svctest/` fixtures are left untouched (see
  [`rootfs/README.md`](../rootfs/README.md)).

Each packing of a disk image signs the kernel, the ELF images under `services/`, `programs/` and
`tests/` and every other file a bundle list names in place, before it composes the ESP, so each
ends in a signature trailer
([signing.md § Signed Object Format](signing.md#signed-object-format)); the bootloader verifies
the kernel and each bundle entry, and procmgr every image it creates, and each loads only the body
the verifier returns. In
`bootstrap.bundle` every entry is its body plus a trailer, the data files included
([xtask/README.md § Signing](../xtask/README.md#signing)).

The disk image is assembled by xtask after the sysroot is populated. Cargo's
own `target/` directory contains intermediate compilation artifacts and is
not part of the sysroot.

### Symbols Store

`cargo xtask build` installs every image procmgr loads, those under `services/`, `programs/` and
`tests/`, stripped with `llvm-objcopy --strip-all`: no symbol table, no debug information, no
`.comment`. procmgr reads an image whole through the filesystem to create a process, so a byte
no loader maps costs every create of that image. The strip keeps the loadable segments, the
section headers, and the notes: the `.note.seraph.*` notes the loaders find through the section
headers, and the build-id note. The kernel and the bootloader, which the firmware and the
bootloader load, are installed as linked.

The link output of every image the build installs, the kernel's and the bootloader's included, is
kept in `symbols/`, beside the sysroot:

```
symbols/
  manifest            # "arch <arch>", then one line per installed image,
                      # "<install path> <store file>", in path order
  <build-id>.elf      # An image's link output, named by the hex
                      # descriptor of its build-id note
  <GUID><age>.pdb     # x86-64: the bootloader's PDB, named by the
                      # CodeView record of /boot/boot.efi
```

The store holds the files of the images installed now: a rebuild of an image replaces its file.
No pack reads it, and `cargo xtask clean` removes it with the sysroot.

A host tool that resolves an address or a symbol of an installed image reads the image's own
symbols when it carries them (the kernel's), and otherwise the store file of the image's build
id, which it refuses unless that file's own build-id note is the image's: an image rebuilt since
a boot, or the store of another build, gives no symbols rather than wrong ones. The tools are
`cargo xtask symbolize`, the crash reports `run-parallel` writes, `test-core-death`, `test-gdb`,
and the GDB command line `run --debug-target` prints
([xtask/README.md](../xtask/README.md#cargo-xtask-symbolize) § `cargo xtask symbolize`).

The riscv64 bootloader is a flat binary that `llvm-objcopy -O binary` makes from its ELF; the
note is in its data, and the manifest names its ELF's store file as `/boot/boot.efi`'s. The
x86-64 bootloader's PDB is kept under the name symbol servers give it, the GUID of its `CodeView`
record in hex and then the record's age.

A release publishes the store of each architecture's release build as one archive beside the
disk image ([conventions.md](conventions.md#release-production) § Release Production);
`cargo xtask symbolize --symbols <dir>` reads an unpacked archive.

---

## Convenience Commands

All build, run, clean, and test operations go through `cargo xtask`. The
authoritative command reference — every subcommand, every flag, expected
behavior — lives in [`xtask/README.md`](../xtask/README.md).

`build` and `run` are intentionally decoupled: `run` is a pure runner and
does not build, so a typical workflow is `cargo xtask build` followed by
`cargo xtask run` (or `cargo xtask run-parallel` for stress).

---

## QEMU and Firmware

Seraph boots via its own UEFI bootloader on both architectures. This requires
UEFI firmware in QEMU — SeaBIOS cannot load UEFI applications.

**x86-64:** Requires OVMF (`edk2-ovmf` / `ovmf` / `edk2-x86_64-code.fd`,
distro-dependent). `cargo xtask run` searches per-platform default paths
(Linux FHS, macOS Homebrew, BSD ports), or honours the `SERAPH_OVMF_CODE`
env var for direct override on non-FHS or unsupported hosts. The bootloader
`.efi` reaches OVMF via the GPT image's ESP partition, attached to the
guest as a virtio-blk-pci device.

**RISC-V:** Requires `edk2-riscv64` firmware. `cargo xtask run` searches
per-platform default paths and pads `RISCV_VIRT_CODE.fd` / `RISCV_VIRT_VARS.fd`
to 32 MiB in cached copies under `target/xtask/firmware/riscv/` (the code image
regenerated only when stale, the vars template re-copied every launch); QEMU virt
≥ 9.0 requires exactly 32 MiB. `SERAPH_RISCV_CODE` and `SERAPH_RISCV_VARS` override discovery;
they are an all-or-nothing pair (setting only one is rejected).

**TPM (opt-in):** `cargo xtask test-tpm` (x86-64) attaches a TPM 2.0 to the guest, QEMU's
`tpm-tis` or `tpm-crb` device backed by `swtpm`, a software TPM 2.0 emulator, which it
starts on a fresh state directory for each boot; it needs the `swtpm` package on the host. No
other launch attaches a TPM, so the reference boot set and every other command need neither
`swtpm` nor the device, and a TPM launch leaves `virtio-rng-pci` out so the TPM is the
`hwrng` class's only member ([xtask/README.md](../xtask/README.md#cargo-xtask-test-tpm);
[services/drivers/docs/tpm.md](../services/drivers/docs/tpm.md)).

**Acceleration:** controlled by `SERAPH_ACCEL` (`auto` / `tcg` / `kvm` /
`hvf` / `whpx` / `nvmm`). Default `auto` runs per-host detection: KVM on
Linux (`/dev/kvm` opened O_RDWR), HVF on macOS, WHPX on Windows, NVMM on
NetBSD, or TCG elsewhere. Cross-arch guests (riscv64 on x86, etc.) always
resolve to TCG. The user-facing command reference plus the full env-var
table lives in [`xtask/README.md`](../xtask/README.md#environment-variables).

**Minimum QEMU version:** QEMU ≥ 9.0 is required: 8.0 brought V extension support, and 9.0
the non-experimental `ssaia` and `smaia` CPU properties. `xtask/src/qemu.rs` passes
`-machine virt,aia=aplic-imsic` and
`-cpu rv64,v=true,zba=true,zbb=true,zbs=true,svpbmt=on,svinval=on,svnapot=on,ssaia=on,smaia=on`
followed by `,smstateen=on,svadu=off,svade=on`, the `--riscv-zkr` suffix (default `,zkr=on`)
and the `--riscv-mmu` satp-mode suffix (default `,sv57=off`) for RISC-V and
`-cpu max,migratable=no` on x86-64 TCG, plus the `--x86-paging` `la57` suffix (default
`,la57=off`, appended to every x86-64 accelerator's `-cpu` model) and the
`--x86-shadow-stack` `cet-ss` suffix (default `,cet-ss=off`, appended likewise when the QEMU's
`-cpu help` lists the `cet-ss` flag; a QEMU without the flag, the 10.2 of the CI image among
them, cannot offer CET shadow stacks, so the default appends nothing there and `on` is refused
before launch). The explicit feature string is the source of truth on every supported QEMU,
including the 10.2 the pinned CI image ships (§ Continuous Integration); the supervisor paging
extensions (Svpbmt, Svinval, Svnapot) are required by the kernel, whose paging subsystem refuses
CPUs that lack them during boot, before the first userspace mapping, and so are AIA (Ssaia, with
the machine's APLIC and IMSIC), without
which its interrupt initialisation halts the boot, and Ssstateen, whose `sstateen0` the kernel
writes on every hart and without which it halts the boot (see
[platform-requirements.md](platform-requirements.md)). QEMU's `rv64` model leaves Smstateen off,
so `smstateen=on` gives the hart the state-enable CSRs, and the bundled OpenSBI grants S-mode
`sstateen0` and `senvcfg` (`mstateen0.SE0` and `mstateen0.ENVCFG`) on a hart that has them, and
the AIA CSRs (`mstateen0.CSRIND` and `mstateen0.IMSIC`) on a hart with Smaia; the property is
present from QEMU 9.0.
The `rv64` model enables Svadu and leaves Svade off, which with the bundled OpenSBI turns on
hardware A/D updating (`menvcfg.ADUE`). `svadu=off,svade=on` boots the Svade baseline instead, so
an access that finds A clear faults and the kernel's fault path sets the bit
([platform-requirements.md](platform-requirements.md); both properties are present from QEMU 9.0).
`zkr=on` gives the hart the Zkr entropy source, whose `seed` CSR the bundled OpenSBI grants
S-mode when the hart implements it, so the kernel's pool seeds from it beside the firmware boot
seed and the boot log shows
`entropy: seeded from hardware RNG`; the source is optional, and `--riscv-zkr off` boots without
it ([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Sources and graceful
degradation). The named `-cpu rva23s64` model
(QEMU ≥ 10.0, 2025-04) adds the remaining RVA23 mandates; `xtask` does not expose it, and the
explicit string stays so the 9.0 minimum holds.

---

## Testing

### Kernel Testing Strategy

**Host unit tests** — Pure algorithmic modules (buddy allocator, capability
tree, scheduler run queues) keep hardware dependencies behind trait boundaries. The kernel
crate's root uses `#![cfg_attr(not(test), no_std)]`, so `cargo xtask test --component kernel`
runs these modules on the host under the standard test harness, and again built for riscv64
under QEMU's user-mode emulator, so each architecture's module runs its tests as `current`.

**QEMU integration tests** — Code requiring real hardware (page tables, interrupts, context
switching) is tested under QEMU by the [`core/ktest`](../core/ktest/README.md) harness, which
runs tests sequentially and reports results over serial.

### Running Tests

```sh
cargo xtask test                        # all workspace tests
cargo xtask test --component kernel     # single crate
```

Before it runs the tests, `cargo xtask test` lints the test code: Clippy over the test
configuration of the selected crates for the Linux target of each architecture (`xtask`, which
builds only against the prebuilt `std`, for the host target alone), with all warnings treated as
errors ([coding-standards.md](coding-standards.md#clippy) § Clippy;
[xtask/README.md](../xtask/README.md) § `cargo xtask test`). After the host run, it builds the
tests of the selected crates, `xtask` and its wrapper shim left out, for
`riscv64gc-unknown-linux-gnu` and runs them under `qemu-riscv64`, so a test gated on riscv64 runs
on an x86_64 host ([§ Toolchain](#toolchain) lists the packages that run needs).

For test naming conventions and requirements (what must be tested, what should not), see
[coding-standards.md](coding-standards.md#d-testing-invariants).

---

## xtask

`xtask/` is a Rust binary crate that runs on the host. It is the primary build
interface; invoke it with `cargo xtask <command>`.

See [`xtask/README.md`](../xtask/README.md) for the full command reference and
[`xtask/src/main.rs`](../xtask/src/main.rs) for the dispatch entry point.

---

## Continuous Integration

CI workflows live in `.github/workflows/`. Local equivalents are the
`cargo xtask` commands documented above.

| Workflow | Trigger | Purpose |
|---|---|---|
| `build-test.yml` | push to `master`, PR to `master`, manual dispatch | Light validation: one `host-tests` job runs `cargo xtask lint-docs`, on a pull request `cargo xtask commit-check` over its commits, and then, after installing the riscv64 test emulation packages, `cargo xtask test`, which lints the test code before it runs the tests on the host and under riscv64 emulation; a `qemu-debs` job (`qemu-debs.yml`) provides the QEMU and firmware packages (below); the matrix `validate` job builds each `arch × profile` cell, then per-tester either stages a recipe (svctest also co-stages `crasher`, `memhog` and `stopsrc` and drops `crashd`), drops the autostarted `terminal`, and runs `mkdisk --repack-only` (svctest, usertest), or re-composes the bundle via `compose-bundle --harness ktest`, checks the staged images' FAT volumes with `check-disk` (`fsck.fat -n`), and runs one `run-parallel --parallel 1 --runs 1` iteration with `--save-logs`, under a per-cell `--timeout`: the rule [testing.md § Coverage tiers](testing.md#coverage-tiers) gives the boundary budgets, applied to the cell's worst CI pass with ktest's 100 s bound at 4 CPUs as the added bound for every cell, and re-derived when that worst changes, which a pass taking more than half its budget flags with a warning annotation on the run; the non-passing runs' logs upload as one artifact per cell at the repository's default retention, and every run's saved log, a PASS included, as a second artifact kept 14 days, each with the symbolized crash reports `run-parallel` writes beside its logs; ktest cells then run `test-kaslr` and `test-map-redo`, svctest cells run `test-crash-report --expect none --log` on the log their boot saved, and usertest cells run `test-crash-report --expect reports --log` on theirs and `test-log-level`, then re-mirror the default boot (`mkdisk`) and run `test-terminal`, `test-wedge`, `test-reboot`, `test-core-death` and `test-signing`, plus `test-vmgenid` and `test-powerbutton` on x86_64. |
| `burnin.yml` | tag push (`v*.*.*`), manual dispatch | Heavy validation: a `qemu-debs` job (`qemu-debs.yml`) provides the QEMU and firmware packages (below); the `arch × profile × tester` matrix builds each cell, stages that one harness (svctest/usertest drop the autostarted `terminal` and `mkdisk --repack-only`; ktest via `compose-bundle --harness ktest`), then burns it in with `run-parallel --parallel 2 --runs 20` under a per-cell `--timeout`, derived from the cell's worst 2-way burn-in pass by the rule the `validate` job's budgets follow, and re-derived when that worst changes. |
| `qemu-debs.yml` | `workflow_call` from `build-test.yml` and `burnin.yml` | One `qemu-debs` job downloads the QEMU and firmware packages into the cache entry the caller's booting jobs install from (below). |
| `release.yml` | tag push (`v*.*.*`), manual dispatch against a `v*.*.*` tag ref (jobs refuse branch refs) | A `preflight` job verifies the workspace version matches the tag and `docs/releases/<tag>.md` exists and follows the template (per [docs/releases/README.md](releases/README.md#source-of-truth)); then builds release-profile disk images per architecture, compresses each and the archive of its build's symbols store (§ Symbols Store) with zstd, generates `SHA256SUMS`, creates a draft GitHub Release whose body is `docs/releases/<tag>.md`. |

The jobs that boot under QEMU (`validate` in `build-test.yml` and `burnin`
in `burnin.yml`) install it and run on the pinned `ubuntu-26.04` runner
image, whose archive ships `qemu-system-riscv64` in the `qemu-system-riscv`
package (QEMU 10.2). The composite action
`.github/actions/qemu-packages/action.yml` holds the install list (QEMU,
its firmware, and dosfstools, whose `fsck.fat` `check-disk` runs) and the
apt flags (no recommends) once; its `mode` input selects the cache key, the
download, or the install, and the download and install calls pass the
package directory as its `dir` input. Every booting cell `needs:` its
workflow's `qemu-debs` job, which runs on the same pinned image because the
downloaded set is resolved against that image's installed packages. The job
downloads the list's resolved `.deb` set once into an `actions/cache` entry
keyed `qemu-debs-<ImageOS>-<ImageVersion>-<action hash>` (the runner
image's version variables and the first 16 hex digits of the action file's
`hashFiles` digest), and downloads nothing
when the entry exists. A download whose fetch from the image's apt mirror
fails or exceeds 120 s rewrites the apt sources, the image's
`/etc/apt/apt-mirrors.txt` mirror list included, from
`azure.archive.ubuntu.com` to `archive.ubuntu.com` and retries once, bounded
at 1200 s. Each booting cell restores the entry by the key the job outputs
and installs from it with apt's sources disabled, so it fetches nothing.
When that offline install fails, as when the entry is absent or the set does
not resolve against the cell's image, the cell runs the same bounded
download itself and installs offline from it. When the `qemu-debs` job
fails, the booting cells are skipped and the run fails. An entry saved on
`master` is readable from every branch and tag, so both workflows and later
runs share one entry per key. The pin, the install list and the cache key
move together: the key derives from the image version and the action, so a
change to the list, the flags or the pinned image yields a new entry.

The `validate`, `burnin` and `build-image` jobs each have a step that sets
`SERAPH_SIGNING_DIR=$RUNNER_TEMP/seraph-signing`, so each job generates its signing keys outside
the checkout on its first build and discards them
([signing.md § Signing](signing.md#signing)).

The `build-image` job of `release.yml` boots nothing (its one `cargo xtask`
command is `build`), so it installs no QEMU and runs on `ubuntu-latest`.

`build-test.yml` cancels stacked runs on the same ref
(`cancel-in-progress: true`). `burnin.yml` and `release.yml` do not
cancel on the same ref — a tag-push run completes even if a later tag
pushes.

Harness staging and the per-cell boot sequence are specified in
[testing.md](testing.md#gating).

The merge-gating rule (CI must pass green before merge) lives in
[conventions.md](conventions.md#branch-and-pr-workflow).

---

## Summarized By

[README.md](../README.md), [core/boot/README.md](../core/boot/README.md),
[ELF Loading](../core/boot/docs/elf-loading.md),
[RISC-V UEFI Boot](../core/boot/docs/riscv-uefi-boot.md),
[core/kernel/README.md](../core/kernel/README.md),
[Return-Address Integrity](../core/kernel/docs/return-address-integrity.md),
[Boot Media](boot-media.md), [System Bootstrap](bootstrap.md),
[Coding Standards](coding-standards.md), [Platform Requirements](platform-requirements.md),
[docs/releases/README.md](releases/README.md), [Testing](testing.md),
[rootfs/README.md](../rootfs/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/drivers/README.md](../services/drivers/README.md),
[Driver Model](../services/drivers/docs/driver-model.md),
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md),
[xtask/README.md](../xtask/README.md), [xtask/targets/README.md](../xtask/targets/README.md)
