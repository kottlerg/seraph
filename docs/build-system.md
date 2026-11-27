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

Every pack of a disk image (`cargo xtask build`'s, `cargo xtask mkdisk`'s, and each test's that
repacks) checks the images it wrote with `fsck.fat` from dosfstools
([xtask/README.md](../xtask/README.md#the-image-check) § The image check), and so do the image
check's host tests that `cargo xtask test` runs, so both need the `dosfstools` package on the host
(the same name on Debian, Ubuntu, Fedora, Arch, Homebrew and FreeBSD). A pack fails, naming it,
when it finds no `fsck.fat` on `PATH` or, on a Unix host, in `/usr/local/sbin`, `/usr/sbin` or
`/sbin`, where distributions install it and which an unprivileged user's `PATH` can lack.

A build with `SERAPH_SECURE_BOOT_KEY` and `SERAPH_SECURE_BOOT_CERT` set Authenticode-signs the
bootloader with `sbsign` and checks it with `sbverify`, from sbsigntools (`sbsigntool` on Debian
and Ubuntu, `sbsigntools` on Fedora and Arch); a build without them needs neither
([signing.md](signing.md) § Secure Boot). `cargo xtask test secureboot` needs them too, with
`openssl`, which generates its keys, and virt-firmware's `virt-fw-vars`, which enrols them in a
variable store (`python3-virt-firmware` on Debian, Ubuntu and Fedora, `virt-firmware` on Arch;
`pip install virt-firmware` elsewhere). Each fails, naming the tool, when one is missing.

`cargo xtask symbolize` reads DWARF and symbol tables in Rust, with the `addr2line` and `object`
crates the toolchain's sysroot ships ([coding-standards.md](coding-standards.md#dependencies)
§ Dependencies), so symbolizing needs no host tool beyond the toolchain. Debugging a guest
through QEMU's gdbstub ([testing.md § Troubleshooting](testing.md#troubleshooting)) needs a host
GDB that supports the guest's architecture: a riscv64 guest needs a GDB built for RISC-V as well
as the host, such as one configured with `--enable-targets=all` or a distribution's multi-target
package (`gdb-multiarch` on Debian and Ubuntu). `gdb -batch -ex 'set architecture riscv:rv64'`
fails on a GDB without it.

Bounded proofs ([testing.md](testing.md#bounded-verification) § Bounded verification) run with
Kani, pinned to one release: `KANI_VERSION` in `xtask/src/commands/kani.rs`, today 0.68.0. A Kani
release builds the code it verifies with a nightly of its own (0.68.0 with `nightly-2026-08-21`),
which `cargo kani setup` installs beside the pinned toolchain. Kani runs on Linux and macOS hosts:
install it with `cargo install --locked kani-verifier --version <pin>`, then
`cargo kani setup`. `cargo xtask kani` checks `cargo kani --version` against the pin and fails,
naming these commands, on another release or none.

The crates Kani verifies, each in its test configuration, and every crate they depend on build with
both nightlies, the tree's and the pin's, since `cargo kani` builds the whole dependency graph with
the pin's. A crate of that graph that uses a library API stable on the tree's nightly but not yet on
the pin's carries `#![cfg_attr(kani, feature(<name>))]`, the one feature-gate attribute this
permits, and drops it once the pin's nightly has the API stable (the kernel carries
`unsafe_cell_access`). A toolchain bump runs `cargo xtask kani` too, and moves the pin to the newest
Kani release that builds the tree; until one does, the bump waits.

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
(`process_abi::STACK_GUARD_PAGES`;
[`threadstack`](../services/fixtures/program-modes/README.md#threadstack)'s `splitframe` and `span`
modes check it), where x86-64, whose `call` pushes the return address, needs one. The two floors:

- `x86_64-seraph.json` — **x86-64-v3** psABI feature level: SSE2/3/SSSE3/
  SSE4.1/4.2, AVX, AVX2, FMA, BMI1/2, LZCNT, MOVBE, F16C, POPCNT, CX16, LAHF/SAHF,
  plus XSAVE/XSAVEOPT for the switch-out save.
- `riscv64a23-seraph.json` — a subset of the **RVA23U64** userspace profile (RVA23 v1.0,
  ratified 2024-10-21): IMAFDCV plus the Zba/Zbb/Zbs bitmanip set,
  hard-float LP64D ABI.

These JSONs pin the *instruction baseline* (the psABI feature level the toolchain emits). The
*runtime platform / silicon-era contract* — which CPU and platform features the kernel requires,
uses opportunistically, or does not support, and the boot-time feature-gate that enforces it — is in
[platform-requirements.md](platform-requirements.md).

Userspace correctness under preemption is provided by an FP/SIMD/V save on switch-out and a
load on switch-in unless the registers still hold the thread's state; the state is live whenever
a user thread runs. The discipline is specified in
[scheduler.md](../core/kernel/docs/scheduler.md#what-gets-saved-and-restored);
the per-arch primitives are in `core/kernel/src/arch/{x86_64,riscv64}/fpu.rs`.

The x86-64 bootloader uses the built-in `x86_64-unknown-uefi` target, so no
custom JSON is needed. The RISC-V bootloader uses
`riscv64imac-seraph-uefi.json` because no equivalent built-in target exists.
`cargo xtask build` sets `RUSTFLAGS` for the bootloader build to
`-Zunstable-options` on both architectures, and on riscv64 adds the link
argument of the bootloader's linker script, `core/boot/linker/riscv64-uefi.ld`.
Cargo reads the `.cargo/config.toml` of the current directory and of every
parent directory and joins their `rustflags` arrays, so a checkout nested
under another (a worktree under `.claude/worktrees/`) receives a flag once
for each config file that lists it; `RUSTFLAGS` is used in place of them
all, so the bootloader link is the same from any checkout.

The linker scripts of the kernel (`core/kernel/linker/<arch>.ld`) and of the
riscv64 bootloader are passed by `cargo xtask build`, in the `RUSTFLAGS` of
their builds, as the link argument `-Clink-arg=-T<path>` with the script's
path relative to the workspace root, from which Cargo runs rustc for a
workspace member, so the flags are the same in every checkout
(`Arch::kernel_linker_script` and `Arch::boot_linker_script` in
`xtask/src/arch.rs` name them), and not by a build script, whose
`rerun-if-changed` files Cargo judges by modification time
([§ Continuous Integration](#continuous-integration)). Each crate includes its
script (`include_bytes!` in its `main.rs`), which makes the script an input
Cargo judges by content, so a change to it rebuilds and relinks the image.
Cargo splits `RUSTFLAGS` at whitespace, so neither path holds any, as a host
test checks.

The riscv64 kernel build, and its Clippy pass, run with `RUSTFLAGS` set,
besides the link argument, to `-Zunstable-options -Zemit-stack-sizes` (`RISCV64_KERNEL_RUSTFLAGS` in
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
reason two profiles persist rather than one. A third, `fuzz`, builds only the
fuzz targets (`cargo xtask fuzz`, [testing.md](testing.md#fuzzing) § Fuzzing):
it inherits `release` and sets `panic = "unwind"`, so the engine catches a
panic and goes on, debug assertions and overflow checks on, line tables for a
report's backtrace, and LTO off, since the SanitizerCoverage pass would
instrument the merged module again, the engine's callbacks with it. Cargo names the profiles `dev`
and `release` but writes their output to `target/<triple>/debug/` and
`target/<triple>/release/`; the CI cells and branch-protection status checks
use the directory names `debug`/`release`.

`cargo xtask build` runs every cargo command with `CARGO_INCREMENTAL=0`, the
value the Rust cache action writes to the environment of the CI jobs that use it
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

To read where a build's own instructions come from rather than to step through
them, `--limited-debug <component>[,<component>…]` injects
`profile.<active>.package."<pkg>".debug="limited"` alone: line tables and
function frames, inlined ones included, at the profile's own opt-level, so the
instructions are those a build without it emits (the crate hashes it changes can
reorder functions in the image). `cargo xtask path-account` reads the kernel's
and ktest's this way, and every image's (`all`) for the userspace rows
([xtask/README.md](../xtask/README.md#cargo-xtask-path-account)).
A component `--debug` also names takes `--debug`.

### Opt-level overrides

`cargo xtask build --opt-level <package>=<level>[,...]` builds the named workspace packages at
another opt-level within the active profile
([xtask/README.md](../xtask/README.md#cargo-xtask-build)); a component `--debug` also names is
refused, since `--debug` builds it at `opt-level = 1`. A package is any of the workspace, a
library included, and the override reaches it wherever the build compiles it, in the `-Z
build-std` crates too: an override of `shmem` changes every image that links the standard
library, whose stdio pipe is `shmem`'s ring. Under `--release` the merged module of a binary is
optimized again at that binary's level, so a library's override may not survive into an image.
`cargo xtask compare-images` builds each commit without `--opt-level`, so whether one survives is
read by committing it as a `[profile.<p>.package."<pkg>"]` table in a scratch commit and
comparing that commit with its parent, as the measurement below did.

No package carries an override: the root `Cargo.toml` has no `[profile.<p>.package.<crate>]`
table, and every package builds at the profiles' `opt-level = 2`. A package earns an override
only by a win past `bench-check`'s band on a benchmark of its own hot path, with its binaries'
`.text` growing by at most 5% and its largest stack frame by at most 256 bytes, and both
architectures reaching the pass marker. The candidates were measured at `opt-level = 3` against
`opt-level = 2` in the release profile, the one the `bench` cell gates and hardware runs, after
the ring and the renderer gained their bulk copies, five ubench boots of each build at one CPU
([testing.md](testing.md#benchmarks-bench-cell) § Benchmarks):

| Package | Images that change | Icount, x86_64 | Icount, riscv64 | Host time, x86_64 | Cost |
|---|---|---|---|---|---|
| `framebuffer` | The driver alone | `console_write` 5.7% fewer instructions at both sizes | `console_write` 0.56% fewer, inside the band | `console_write` within the boot-to-boot spread (lowest p50 0.7% above `opt-level = 2`'s at 4096 bytes; the five boots of one build spread by 10% to 20%) | `.text` 9.4% larger on x86_64 and 7.4% on riscv64; on riscv64 the service loop's frame gains vector register spills, a size that grows with the hardware's vector length |
| `shmem` | Every image that links `std`, and those that link `shmem` directly | No `shmem_ring` or `console_write` row moves | No row moves | `shmem_ring` no faster (4096 and 65536 bytes 1% to 6% slower) | None needed: no win |

Neither is kept. `framebuffer`'s win is past the band on x86_64 alone, does not show as time,
and costs more `.text` than the bound allows. `shmem`'s ring copies are calls to `memcpy`, whose
code is not `shmem`'s, so its level does not reach the measured copy. The rows these rest on are
`console_write` at both sizes and `shmem_ring` at every size, measured before the `shmem_ring`
rows were split by the ring index they start at (`wrap=`); every row of the earlier set ran the
whole transfer in its window.

`kernel` is not a candidate. The override's unit is the package, so `opt-level = 3` on
`kernel` would raise the whole kernel; its targets have no vector unit to use
(`x86_64-seraph-none.json` turns SSE and AVX off and floats in software;
`riscv64imac-seraph-none.json` has no V), which leaves `opt-level = 3` loop unrolling alone,
and its framebuffer (`core/kernel/src/framebuffer.rs`) draws only its own direct console lines,
no hot path.

---

## Build Output: the Sysroot

Build artifacts are staged in `sysroot/`, which is then packaged into the
top-level `disk.img` GPT image consumed by QEMU (with the data and swap partitions on
a second image, `disk-data.img`, which the staged storage statement names at the PCI location its
boot places it, under
`mkdisk --split-data`). The sysroot is built for
one architecture at a time; the active architecture is recorded in
`sysroot/.arch`. Switching architectures requires a clean rebuild. The harness
whose bundle every pack composes, `init` or `ktest`, is recorded in
`sysroot/.harness`: `cargo xtask build` records `init`, and
`cargo xtask mkdisk --harness` the harness it is given. Every pack records the test harnesses the
image it packed boots in `sysroot/.image-harness` (`ktest` for the ktest bundle, otherwise each of
`svctest`, `usertest` and `ubench` whose recipe it staged on a layer the image holds), which
`cargo xtask run --runs` binds its default pass marker and its reading of a harness's death to
([xtask/README.md § `cargo xtask run`](../xtask/README.md#cargo-xtask-run)). A focused ktest build
(`cargo xtask build --ktest-only`) records its test-name prefixes in `sysroot/.ktest-selection`,
which a build of the full ktest removes; a pack of the ktest bundle copies them onto the `ktest`
line of `sysroot/.image-harness`, and `run --runs` refuses the image of a focused ktest, as that
record names it, without `--ktest-only-ok`.

Cargo's own output stays in `target/`. The builds of the std-user programs compile `std`, with
`core` and `alloc`, from the seraph toolchain mirror, `target/seraph-toolchain/`, which carries
the `std` overlay ([`xtask/src/rust_src.rs`](../xtask/src/rust_src.rs)); every other build
compiles `core` and `alloc` from the toolchain's own `rust-src`. The mirror's builds take
`target/seraph-build-<format>/` as Cargo's build directory, and their binaries still land in
`target/<triple>/<profile>/` with every other build's. Two builds of one library package from
two source paths cannot share a build directory: a host build script, `compiler_builtins`'s among
them, is one unit for every target, its fingerprint records the path it was built from, and each
kind of build would find the other's path there and rebuild the script, `compiler_builtins` and
`alloc` for every target. `cargo xtask clean --all` removes `target/`, both directories with it.

Cargo records no source file of a unit that `-Z build-std` compiles: it does not count such a unit
as local, and drops every path of its dep-info under the package's root. It keeps the files outside
that root (those `std` includes from `backtrace` and `portable-simd`, and `core` from `stdarch`)
and the environment variables the unit reads. So three things judge the units of the mirror's
builds current:

- The toolchain's library sources are fixed by its version, which every unit's fingerprint holds.
- `std`'s overlay is in the mirror's stamp, a hash of `runtime/ruststd/src/`, of
  [`xtask/src/rust_src.rs`](../xtask/src/rust_src.rs) and of the toolchain's version. A stamp that
  differs from the tree's makes xtask assemble the mirror anew, which writes `std`'s patched
  `build.rs` again: `std`'s build script names that file, and Cargo judges a build script's files
  by time, so the script reruns and `std` and every unit that depends on it are rebuilt.
- The workspace crates `std` depends on (`STD_WORKSPACE_DEPS` in `xtask/src/rust_src.rs`, which
  lists every path dependency of each of them too) each read `SERAPH_STD_DEPS_DIGEST` under
  `rustc-dep-of-std`, which only `-Z build-std` enables. Every cargo command through the mirror
  sets it to the SHA-512 of the names and contents of every file of those crates but Markdown,
  so a change to any of them changes a value their units recorded, and rebuilds them, `std`, and
  every std-user program. Markdown is left out, as the cells and the build carry's key leave it
  out: no unit reads it, and a change to it alone owes no build job, so a digest that saw it would
  make every later pull request's build jobs rebuild these units after a merge that saved no carry
  entry. The mirror's stamp leaves it out of `runtime/ruststd/src/` by the same rule. Host tests
  check that each listed crate reads the digest, that the list holds every path dependency of its
  crates, and that the digest and the stamp hash exactly the files of those crates and of
  `runtime/ruststd/src/` whose change owes every build job, so a Markdown file a source reads,
  which the cells place by that source, fails them.

The build directory's name carries its format, the rules its units are judged by
(`BUILD_DIR` in `xtask/src/rust_src.rs`, `target/seraph-build-1/`): a unit compiled under older
rules can pass as current under newer ones, so each format builds in a directory of its own, which
no xtask of another format writes into, and xtask removes the directories of older formats
(`target/seraph-build/`, of the builds before the digest) before the build.

```
sysroot/
  .arch                   # "x86_64" or "riscv64"
  .harness                # "init" or "ktest": the bundle every pack composes
  .image-harness          # The test harnesses the packed image boots, and its ktest's selection
  .ktest-selection        # A focused ktest build's test-name prefixes (build --ktest-only)
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
                          # so its bundle holds no module but the
                          # boot-time policy every bundle carries.
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
  programs/               # Userspace programs sourced from programs/
                          # in the repo tree (the InstallDest::Programs
                          # entries in xtask/src/commands/build.rs
                          # SPECS). Loaded by procmgr from the root
                          # partition via VFS at runtime.
  tests/                  # Test harnesses, per-program testers, and
                          # test fixtures: kernel-surface harness
                          # (ktest), services-surface (svctest),
                          # programs-surface orchestrator (usertest),
                          # and the ubench benchmark suite. Some
                          # test-only artifacts install outside it.
  tests/fixtures/         # Test fixtures a harness recipe starts as
                          # services, sourced from services/fixtures/
                          # (the InstallDest::TestsFixtures entries in
                          # xtask/src/commands/build.rs SPECS).
  tests/fixtures/programs/ # Test fixtures spawned as programs, sourced
                          # from services/fixtures/ (the
                          # InstallDest::TestsFixturesPrograms entries),
                          # signed in the program role.
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
                          # which svctest also uses as scratch space;
                          # data/svctest/signed/ is signed in the data
                          # role (docs/signing.md § Signing).
  crash/                  # Created empty: the directory crashd writes
                          # cores to (services/crashd/docs/core-format.md).
```

The UEFI firmware discovers the bootloader at `EFI/BOOT/BOOT<arch>.EFI`
(the UEFI specification's fallback boot path). The kernel and the bundle of
boot-loaded services live alongside it under `EFI/seraph/`, the Seraph vendor
directory within the EFI partition.

`tests/` holds the test harnesses, per-program testers, and test fixtures,
but test-only artifacts also install under `services/drivers/`,
`config/svcmgr/tests/`, `config/devmgr/tests/`, and `data/`;
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

The ESP is derived from the installed files ([boot-media.md](boot-media.md)): every object on it,
the bootloader and the kernel included, is a byte copy of a file installed in the sysroot (on the
root partition, except for the kernel layer's image, which holds none), and composing it copies
files, signs nothing and reads no key. Every pack composes it as its last
step before it writes the images, and refuses it unless every object on it equals its installed
file, so the ESP of every image equals the installed files. The
bundle's entries are the installed files that the recorded harness's bundle list names
(`config/bundle/<harness>.<arch>.list` where the architectures differ, `<harness>.list` where
they do not, from [`rootfs/config/bundle/`](../rootfs/config/bundle/)), each by its install path;
the list's `init` line names the object of the `init` slot. The data files the build
installs under `/config/` from the repository (`xtask/src/sysroot.rs`, `data_files`) are the
log-level configuration, which a list names, and the platform description tables, which no list
names.

The `esp/` and root-partition trees are populated from two sources:

- Compiled binaries are installed by `cargo xtask build` to their
  destinations (`boot/kernel` for the kernel and `boot/boot.efi` for the
  bootloader, which reach the ESP as copies; boot modules reach the ESP only
  inside `bootstrap.bundle`),
  `services/<name>`, `services/drivers/<name>`,
  `services/fs/<name>`, or `programs/<name>` for std-userspace
  binaries, `tests/<name>` or `tests/programs/<name>` for harness
  binaries and per-program testers, `tests/fixtures/<name>` or
  `tests/fixtures/programs/<name>` for the test fixtures,
  `tests/drivers/<name>` for the test-only drivers bound on demand).
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

The store file of an image installed stripped is its link output rewritten by `llvm-objcopy` with
no option: every section kept, and the segments laid out as the strip lays them out, so its
program headers are byte-identical to the installed image's. A debugger relocating a
position-independent executable compares the program headers it reads at the auxiliary vector's
`AT_PHDR`, in the process's memory or a core's copy of the image's first page, against its
executable's, and applies no displacement when they differ. The link output's own would differ
on riscv64: lld places `.comment` between the last `PT_LOAD` and the `.riscv.attributes`
section the `PT_RISCV_ATTRIBUTES` segment covers, and any `llvm-objcopy` rewrite moves that
segment up to the `PT_LOAD`'s end. The build fails when a store file's program headers or build
id differ from its stripped image's. The kernel's and the bootloader's store files are their link
output, as the kernel is installed.

The store holds the files of the images installed now: a rebuild of an image replaces its file.
No pack reads it, and `cargo xtask clean` removes it with the sysroot.

A host tool that resolves an address or a symbol of an installed image reads the image's own
symbols when it carries them (the kernel's), and otherwise the store file of the image's build
id, which it refuses unless that file's own build-id note is the image's: an image rebuilt since
a boot, or the store of another build, gives no symbols rather than wrong ones. The tools are
`cargo xtask symbolize`, the crash reports `run --runs` writes, the `shutdown` and `debug-port`
cases, and the GDB command line `run --debug-target` prints
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

All build, run, clean, and test operations go through `cargo xtask`. The four core commands are
`build` (compile the components and pack the disk image), `run` (boot the sysroot under QEMU),
`clean` (remove the sysroot, the symbols store and the disk images) and `test` (the host-side
tests). [`xtask/README.md`](../xtask/README.md) is the one command reference: every command,
every flag, expected behavior.

`build` and `test` check that the Rust source is formatted (`cargo fmt --check`) and fail on
a file that is not, naming its file and line; neither rewrites source, so a contributor runs
`cargo fmt --all` before committing
([coding-standards.md § Formatters](coding-standards.md#formatters)).

`build` and `run` are intentionally decoupled: `run` is a pure runner and
does not build, so a typical workflow is `cargo xtask build` followed by
`cargo xtask run` (or `cargo xtask run --runs N` for unattended boots, each classified by its
log).

---

## QEMU and Firmware

Seraph boots via its own UEFI bootloader on both architectures. This requires
UEFI firmware in QEMU — SeaBIOS cannot load UEFI applications.

**x86-64:** Requires OVMF (`edk2-ovmf` / `ovmf` / `edk2-x86_64-code.fd`,
distro-dependent): a code image and the variable-store template of the same build.
`cargo xtask run` searches per-platform default paths (Linux FHS, macOS Homebrew, BSD ports)
for the pair, or honours `SERAPH_OVMF_CODE` and `SERAPH_OVMF_VARS`, an all-or-nothing pair,
for direct override on non-FHS or unsupported hosts. The bootloader
`.efi` reaches OVMF via the GPT image's ESP partition, attached to the
guest as a virtio-blk-pci device.

**RISC-V:** Requires `edk2-riscv64` firmware. `cargo xtask run` searches
per-platform default paths and pads `RISCV_VIRT_CODE.fd` / `RISCV_VIRT_VARS.fd`
to 32 MiB in cached copies under `target/xtask/firmware/riscv/`, regenerated only when
stale; QEMU virt ≥ 9.0 requires exactly 32 MiB. `SERAPH_RISCV_CODE` and `SERAPH_RISCV_VARS`
override discovery; they are an all-or-nothing pair (setting only one is rejected).

**Variable store:** every launch, on both architectures, boots on a writable variable store of
its own, a fresh copy of the firmware's template beside the read-only code image, so no launch
sees a variable another wrote; the `rollback` and `enrolment` cases keep one store across their
boots
([xtask/README.md](../xtask/README.md#environment-variables)).

**Secure Boot:** the `secureboot` case ([xtask/README.md](../xtask/README.md#the-secureboot-case))
boots on a firmware pair of its own, one built with Secure Boot, found by
`SERAPH_OVMF_SECURE_CODE` with `SERAPH_OVMF_SECURE_VARS` and `SERAPH_RISCV_SECURE_CODE` with
`SERAPH_RISCV_SECURE_VARS` or a per-platform default search; no other launch uses it. A firmware
built without Secure Boot boots every image whatever keys its store holds, so the case fails on
one, naming it. The builds tested, with the store's keys enrolled by `virt-fw-vars`:

| Firmware | Secure Boot |
|---|---|
| OVMF `OVMF_CODE_4M.secboot.fd` (Ubuntu `ovmf` 2025.11), `OVMF_CODE.secboot.4m.fd` (Arch `edk2-ovmf` 202608) | enforces, run with `-machine smm=on` and its variable store behind SMM |
| OVMF `OVMF_CODE_4M.fd`, `OVMF_CODE.4m.fd`, the default pair | built without it |
| RISC-V `RISCV_VIRT_CODE.fd` of Arch's `edk2-riscv64` 202608-1 | enforces |
| RISC-V `RISCV_VIRT_CODE.fd` of Ubuntu's `qemu-efi-riscv64` 2025.11-3ubuntu7.3 (CI's default pair), 7.4 and 2026.05-2ubuntu3, and of Fedora's `edk2-riscv64` | built without it |

CI's riscv64 cells take Arch's `edk2-riscv64` 202608-1 for the case alone (§ Continuous
Integration), its package pinned by version and SHA-256 and fetched from Arch's package mirror,
which holds it while it is the current version, or else from `archive.archlinux.org`, which
keeps every version. A refresh of it is a new version's file name, URLs and hash in
`.github/actions/qemu-packages/action.yml` and a passing `secureboot` case on it. Any
EDK2 `RiscVVirtQemu` build with `SECURE_BOOT_ENABLE` serves as well.

**TPM (opt-in):** `cargo xtask test tpm` (x86-64) attaches a TPM 2.0 to the guest, QEMU's
`tpm-tis` or `tpm-crb` device backed by `swtpm`, a software TPM 2.0 emulator, which it
starts on a fresh state directory for each boot; it needs the `swtpm` package on the host. No
other launch attaches a TPM, so the reference boot set and every other command need neither
`swtpm` nor the device, and a TPM launch leaves `virtio-rng-pci` out so the TPM is the
`hwrng` class's only member ([xtask/README.md](../xtask/README.md#the-tpm-case);
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
followed by `,smstateen=on,svadu=off,svade=on`, the `--idle-wait` suffix (default `,zawrs=off`), the
`--riscv-zkr` suffix (default `,zkr=on`) and the `--riscv-mmu` satp-mode suffix (default
`,sv57=off`) for RISC-V and `-cpu max,migratable=no` on x86-64 TCG, plus the `--idle-wait`
`monitor` suffix (default `,monitor=off`, appended to every x86-64 accelerator's `-cpu` model;
`on` appends `,monitor=on` under TCG and passes `-overcommit cpu-pm=on` under KVM), the
`--x86-paging` `la57` suffix (default
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
degradation). `zawrs=off` and `monitor=off` leave out the monitored wait the kernel's idle loop
takes where every CPU has it ([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md)
§ Idle Thread): under TCG, `WRS.NTO`, and `MWAIT` with more than one vCPU, return at once, so
an idle vCPU offered them spins on its host thread, and a boot takes the wait only with
`--idle-wait on` ([xtask/README.md](../xtask/README.md#cargo-xtask-run)). The named
`-cpu rva23s64` model (QEMU ≥ 10.0, 2025-04) adds the remaining RVA23 mandates; `xtask` does not
expose it, and the explicit string stays so the 9.0 minimum holds.

---

## Testing

### Kernel Testing Strategy

**Host unit tests** — Pure algorithmic modules (buddy allocator, capability
tree, scheduler run queues) keep hardware dependencies behind trait boundaries. The kernel
crate's root uses `#![cfg_attr(not(test), no_std)]`, so `cargo xtask test --component kernel`
runs these modules on the host under the standard test harness, and again built for riscv64
under QEMU's user-mode emulator, so each architecture's module runs its tests as `current`.

**Bounded proofs** — Pure, sequential code whose property is worth proving for every input in a
bound carries Kani harnesses, which `cargo xtask kani` runs
([testing.md § Bounded verification](testing.md#bounded-verification)).

**QEMU integration tests** — Code requiring real hardware (page tables, interrupts, context
switching) is tested under QEMU by the [`core/ktest`](../core/ktest/README.md) harness, which
runs tests sequentially and reports results over serial.

### Running Tests

```sh
cargo xtask test                        # all workspace tests
cargo xtask test --component kernel     # single crate
```

Before it runs the tests, `cargo xtask test` checks the formatting of the selected crates
(`cargo fmt --check`, [coding-standards.md](coding-standards.md#formatters) § Formatters), then
lints the test code: Clippy over the test
configuration of the selected crates for the Linux target of each architecture (`xtask`, which
builds only against the prebuilt `std`, for the host target alone), with all warnings treated as
errors ([coding-standards.md](coding-standards.md#clippy) § Clippy;
[xtask/README.md](../xtask/README.md) § `cargo xtask test`). Over the whole workspace it then
lints the host crates' non-test code as `cargo xtask build` does. After the host run, it builds the
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

xtask's sub-crates ([xtask/README.md](../xtask/README.md#sub-crates) § Sub-crates) are host
artifacts, each built by the command that needs it and never part of an image. One of them,
[`xtask/path-account-plugin`](../xtask/path-account-plugin/README.md), is a QEMU TCG plugin:
`cargo xtask path-account trace` builds it as a host shared object and loads it into the
guest's QEMU with `-plugin`. That command alone needs a QEMU built with TCG plugins (QEMU's
`--enable-plugins`) whose plugin API accepts version 7; it refuses a QEMU
that takes no `-plugin`, and reports QEMU's own refusal of the plugin's version.

---

## Continuous Integration

CI workflows live in `.github/workflows/`. Local equivalents are the
`cargo xtask` commands documented above. No workflow runs on a timer: each runs on a push, a pull
request, a tag, or a manual dispatch, so a test runs where a change requires it.

| Workflow | Trigger | Purpose |
|---|---|---|
| `build-test.yml` | push to `master`, PR to `master`, manual dispatch | Light validation, of the cells the change owes: a `select` job, from a checkout of the whole history and with `actions: read` to list the `master` runs, runs `cargo xtask cells --since-green HEAD^1` on a push and `--since-covered HEAD^1` on a pull request, so a pull request is not charged a `master` commit whose own run is still proving it (on a manual dispatch `--since` its `cells-since` input, whose absence owes every cell; [xtask/README.md § `cargo xtask cells`](../xtask/README.md#cargo-xtask-cells)), writes the step's log to the run's summary, and gives the `build`, `validate` and `bench` jobs the matrices the change owes and the `kani` jobs its base ([conventions.md § CI Gating](conventions.md#ci-gating)); one `host-tests` job runs `cargo xtask lint-docs`, on a pull request `cargo xtask commit-check` over its commits, and then, after installing the riscv64 test emulation packages and dosfstools from the package cache (below), `cargo xtask test`, which checks the formatting of the Rust source, lints the test code and the host crates as `cargo xtask build` does before it runs the tests on the host and under riscv64 emulation; the `kani` jobs (`kani.yml`, below) prove the crates the change can affect, `--since` the base `select` gives them (every crate when it found none), or a manual dispatch's `kani-since` input, whose absence selects every crate, each job skipped when a run of this repository stored its pass unless the dispatch's `kani-prove-all` input asks ([testing.md § Bounded verification](testing.md#bounded-verification)); a `qemu-debs` job (`qemu-debs.yml`) provides the QEMU and firmware packages (below); the matrix `build` job, skipped when `select` owes no cell, builds each tree the owed cells boot once (`cargo xtask build`), one job per `arch × profile` a `validate` cell is owed in and the release trees when the `bench` cell is owed, whose job then builds the bench-only ktest image (`build --release --ktest-bench-only --skip-lints`), and ships each tree to its cells as artifacts (below); the matrix `validate` job, of the cells `select` owes and skipped when it owes none, boots the tree of its `arch × profile`'s build job and builds nothing (a job that `needs:` a matrix job starts once every entry has ended, and the cells run whatever the other entries' outcomes, so a cell whose build failed fails at its fetch under its own name), running the build job's `xtask` binary in place of `cargo xtask`: per-tester it either stages a recipe (svctest through `mkdisk --repack-only --svctest ci`, which co-stages its `ci` fixture set, `crasher`, `crasher-worker`, `crasher-boot`, `crasher-once`, `memhog`, `reserve-creator` and `stopsrc`, and records it for svctest to check, drops every recipe that names a file of the programs layer (the autostarted `terminal` and the default sessiond among them), stages sessiond's, oomd's and crashd's test recipes over the default ones, and packs an image without the programs layer; usertest by copying its recipe, dropping the autostarted `terminal` and running `mkdisk --repack-only`), or re-composes the bundle via `mkdisk --harness ktest`, each pack checking the images it writes (each FAT volume with `fsck.fat -n`, then that the root and data partitions hold only what the image's kind holds, then that every object on the ESP equals its installed file on the root partition; [xtask/README.md § The image check](../xtask/README.md#the-image-check)), and runs one `run --runs 1` boot with `--save-logs`, which passes only on the pass marker of the harness the image boots and fails when the harness dies before it or the boot crashes QEMU ([xtask/README.md § `cargo xtask run`](../xtask/README.md#cargo-xtask-run)), under a per-cell `--timeout`, svctest's with `--crash-reports reports`, its `crash-endpoint` boot (`mkdisk --repack-only --svctest crash-endpoint`, no crashd) and usertest's with `--crash-reports none`: the rule [testing.md § Coverage tiers](testing.md#coverage-tiers) gives the boundary budgets, applied to the cell's worst CI pass with ktest's 100 s bound at 4 CPUs as the added bound for every cell, which also holds usertest's hung tester's bound and the drain after its kill (9 s, [programs/usertest/README.md § Testers](../programs/usertest/README.md#testers)), and re-derived when that worst changes, which a pass taking more than half its budget flags with a warning annotation on the run; the non-passing runs' logs upload as one artifact per cell at the repository's default retention, and every run's saved log, a PASS included, as a second artifact kept 14 days, each with the symbolized crash reports `run` writes beside its logs; each cell then runs `mkdisk --arch A` (the plain repack: it re-mirrors the rootfs with the repository's log levels and no knobs, and keeps the recorded harness) and `cargo xtask test --cell <tester> --arch A --lanes 3`, which runs every case the registry assigns to that tester, in three lanes side by side ([xtask/README.md § Cells](../xtask/README.md#cells)): usertest runs `terminal`, `signing`, `dma-confinement`, `rollback`, `enrolment`, `secureboot`, `wedge`, `vmgenid` (x86_64 only), `storage-roles` and `shutdown`, ktest runs `kaslr`, and svctest runs none; the ktest cell stages the `mapredo` knob (`mkdisk --harness ktest --knob mapredo`) and its own boot carries the redo check and fails on a `SKIP` line (`--fail-also ' SKIP '`; [testing.md § Gating](testing.md#gating)), and the usertest cell packs `services/init/log-levels-vfsd-debug.conf` (`mkdisk --repack-only --log-levels`) and its own boot carries the log-level check; a `fuzz` job, run when `select` owes it (the change reaches the build of the fuzz targets, of the engine or of a crate they fuzz, xtask, or the workflows), runs `cargo xtask fuzz --self-test`, then `cargo xtask fuzz --all` for the default execution count from seed 0 over a cleared working directory, each target under the 20-minute cap of that count, within a `timeout-minutes` of 45, and uploads the failing inputs as an artifact when it fails ([testing.md § Fuzzing](testing.md#fuzzing)); the matrix `bench` job, one cell per architecture, run when `select` owes it, takes the release bench-only ktest image its architecture's release build job built and packs it (`mkdisk --harness ktest`), and when `select` owes the ktest boots boots it under icount three times at one CPU and once at four (`run --icount --save-logs`, each under a 300 s `--timeout`), then stages the init image with ubench's recipe on the services layer (`mkdisk --harness init --ubench`) and boots it the same four times with a framebuffer (`--display framebuffer`, each under a 900 s `--timeout`), runs `cargo xtask bench-check --mode icount` over the eight logs (over the four ubench logs with `--skip-suite ktest` when the ktest boots were not owed), which fails the cell on a gating one-CPU count past its band, a measurement with no baseline, or a benchmark's `FAIL` line ([xtask/README.md § `cargo xtask bench-check`](../xtask/README.md#cargo-xtask-bench-check)), and uploads the logs and the cell's environment as the artifact `bench-<arch>`, which `cargo xtask bench-baseline --from-run` reads; a `summary` job, after every other job whatever their outcomes, fails when one failed or was cancelled, or was skipped although `select` owed it, and is the check branch protection requires ([conventions.md § Branch protection](conventions.md#branch-protection)). |
| `burnin.yml` | tag push (`v*.*.*`), manual dispatch | Heavy validation: the `kani` jobs (`kani.yml`, below) prove every crate that holds a harness, each job skipped when a run of this repository stored its pass unless a dispatch's `kani-prove-all` input asks; a `qemu-debs` job (`qemu-debs.yml`) provides the QEMU and firmware packages (below); the `arch × profile × tester` matrix builds each cell, stages that one harness (svctest through `mkdisk --repack-only --svctest burn-in`; usertest drops the autostarted `terminal` and `mkdisk --repack-only`; ktest via `mkdisk --harness ktest`), then burns it in with `run --parallel 2 --runs 20` under a per-cell `--timeout`, derived from the cell's worst 2-way burn-in pass by the rule the `validate` job's budgets follow, and re-derived when that worst changes; the ktest boots fail on a `SKIP` line (`--fail-also ' SKIP '`). |
| `fuzz.yml` | manual dispatch (one of them in the release host runs, [testing.md § Coverage tiers](testing.md#coverage-tiers)) | The fuzz campaign ([testing.md § Fuzzing](testing.md#fuzzing)): a `targets` job fails a dispatch whose time is not 1 to 2700 seconds, which the campaign job's timeout holds with its build and minimization, and lists the targets (`cargo xtask fuzz --list`), and the matrix `campaign` job runs one job per target side by side, each under a `timeout-minutes` of 60: it restores the newest working corpus of its target the Actions cache still holds (none when no campaign ran within the cache's lifetime, and the run then starts from the checked-in inputs alone), runs `cargo xtask fuzz <target>` for a fixed time (30 minutes, or the dispatch's input of at most 2700 seconds) from a seed of the run's number, minimizes the corpus and saves it under a new cache key, and uploads the failing inputs as an artifact when it fails. It gates no merge. |
| `kani.yml` | `workflow_call` from `build-test.yml` (input `since`, the base of the selection) and `burnin.yml` (none), each with `skip-passed` true unless a dispatch's `kani-prove-all` input asks for every job, and with `actions: read` | The bounded proofs ([testing.md § Bounded verification](testing.md#bounded-verification)): a `plan` job, from a checkout of the whole history, runs `cargo xtask kani --plan`, `--since` the input when one is given and `--skip-passed` when `skip-passed` is true, which writes the jobs the run owes as a matrix, one entry for each crate it selects or for each shard of a crate `SHARDS` splits, and none for a crate it does not select or a job whose pass a run of this repository stored (`kani-pass-<key>`, [testing.md § Bounded verification](testing.md#bounded-verification)), writes its log to the run's summary, and, when it owes none, ends with a notice on the run that no job was owed ([xtask/README.md § `cargo xtask kani`](../xtask/README.md#cargo-xtask-kani)); the matrix `prove` job, run only when the plan owes a job, one job named `prove (<package> <K/N>)` for each entry, installs the Kani release `cargo xtask kani --pin` prints, outside the checkout (`cargo install --locked kani-verifier`, then `cargo kani setup`), runs `cargo xtask kani --component <package> --shard <K/N> --pass-record`, and, when the harnesses it judged are exactly its shard's and all passed, uploads the pass record as the artifact `kani-pass-<key>`, kept 90 days and replacing the artifact of that name an earlier attempt of the run stored, each under a `timeout-minutes` of 40, every entry running whatever the others' outcomes; the `kani-result` job runs in every run and fails when the plan failed, or a `prove` job failed, ran past its timeout or was cancelled, or the `prove` jobs were skipped although the plan owed them, so it is fit to be a required check where a matrix job, which runs only when owed, cannot be. The jobs run in the caller's run, under its concurrency group, so a pull request's newer push cancels them with the rest of its older run. The file is an input of every pass's key, so a change to it proves every crate. |
| `qemu-debs.yml` | `workflow_call` from `build-test.yml` and `burnin.yml` | One `qemu-debs` job seeds the cache entries of the QEMU and firmware packages the caller's booting cells install from (below). |
| `release.yml` | tag push (`v*.*.*`), manual dispatch against a `v*.*.*` tag ref (jobs refuse branch refs) | A `preflight` job verifies the workspace version matches the tag and `docs/releases/<tag>.md` exists and follows the template (per [docs/releases/README.md](releases/README.md#source-of-truth)); then builds release-profile disk images per architecture, installing zstd and the dosfstools whose `fsck.fat` the build's pack runs, compresses each and the archive of its build's symbols store (§ Symbols Store) with zstd, generates `SHA256SUMS`, creates a draft GitHub Release whose body is `docs/releases/<tag>.md`. |

The jobs that boot under QEMU (`validate` and `bench` in `build-test.yml`
and `burnin` in `burnin.yml`), and `build-test.yml`'s `build` job, which boots nothing but packs
and so needs the image check's dosfstools, install it and run on the `ubuntu-26.04` runner label,
whose archive ships `qemu-system-riscv64` in the `qemu-system-riscv`
package (QEMU 10.2). The label names an image, not a version of it: while
GitHub rolls out a new version, the label resolves to more than one
`ImageVersion` within one run, so two cells of one run can run on different
image versions. The composite action
`.github/actions/qemu-packages/action.yml` holds the install list (QEMU,
its firmware, dosfstools, whose `fsck.fat` every pack runs, and the
`secureboot` case's sbsigntool, openssl and python3-virt-firmware), the
apt flags (no recommends), and the riscv64 Secure Boot firmware pin once;
its `mode` input selects `cache` or `install`. The action keeps two
`actions/cache` entries:

- The `.deb` set, keyed `qemu-debs-<ImageOS>-<ImageVersion>-<action hash>`
  (the runner image's version variables and the first 16 hex digits of the
  action file's `hashFiles` digest), in the `qemu-debs` directory. The set
  is resolved against the installed packages of the image version it was
  downloaded on, and a set from another version can fail to install, so
  each version has its own entry.
- The riscv64 Secure Boot firmware, Arch's `edk2-riscv64` package, keyed
  `qemu-firmware-<pin>` (the first 16 hex digits of its pinned SHA-256), in
  the `qemu-firmware` directory. The package is the same file on every image
  version, so every cell reads the one entry.

Every booting cell comes after its workflow's `qemu-debs` job (a `build-test.yml` cell through the
`build` job it `needs:`, which `needs:` `qemu-debs`), which runs the
action in `cache` mode on the same label: it looks both entries up and
downloads and saves each one that is absent, the `.deb` set for the version
it runs on. The `.deb` download fetches the list's resolved set from the
image's apt mirror; a fetch that fails or exceeds 120 s rewrites the apt
sources, the image's `/etc/apt/apt-mirrors.txt` mirror list included, from
`azure.archive.ubuntu.com` to `archive.ubuntu.com` and retries once,
bounded at 1200 s. The firmware download tries the sources the action pins
in turn, Arch's package mirror and then `archive.archlinux.org`, each with
a 30 s connect bound, keeps the first package whose SHA-256 is the pinned
one, and fails the job when no source serves it.
When the `qemu-debs` job fails, the booting cells are skipped and the run
fails.

Each booting cell runs the action in `install` mode. It computes the key
of the image version it runs on itself, restores that `.deb` entry and the
firmware entry, and installs the set with apt's sources disabled, so a cell
whose version has an entry fetches nothing. When the entry is absent, or
its set does not install, the cell runs the same bounded `.deb` download
itself, installs offline from it, and saves the entry under its own key
when the restore missed, so the next run on that version restores it. The
`.deb` fallback leaves the firmware package alone: the cell checks the
restored package's SHA-256 against the pin and keeps it, and fetches it
from Arch's sources only when the firmware entry is absent or the hash
differs, so a cell needs only the Ubuntu mirror while the firmware entry
exists. It then checks the hash again, extracts the package's two
images outside the checkout, and sets `SERAPH_RISCV_SECURE_CODE` and
`SERAPH_RISCV_SECURE_VARS` to them for the job's later steps. An entry is
saved only after its content is in place, a cell's `.deb` set only after
it installed. The cells of one version that miss its entry together each
download the set once, and each tries to save the one key: the first save
wins, and the others log that the key is taken and do not fail.

An entry saved by a run on `master` (a push run) is readable from every
branch and tag, so both workflows and later runs share one entry per key.
An entry saved by a pull-request run is readable only by runs of that pull
request, so the `master` push runs seed the entries every pull request and
tag run restores: the firmware entry once per pin, and a `.deb` entry for
each image version a `master` run's job or cells land on. The pin, the
install list and the keys move together: the `.deb` key derives from the
image version and the action, and the firmware key from the pin, so a
change to the list, the flags, the pin or the image version yields a new
entry.

The `host-tests` job installs its own packages, the riscv64 user-mode emulator, cross compiler
and C library and dosfstools, through the same action with its `set` input `host-tests`: a
`.deb` entry of its own, keyed `host-tests-debs-<ImageOS>-<ImageVersion>-<action hash>`, no
firmware entry, and the bounded download, offline install and save of a booting cell's `install`
mode. No job seeds it: a `master` run's job on a new image version downloads and saves it, and
every later run on that version installs offline.

Cargo judges a unit of the tree current by the checksums of the files rustc read for it, which the
unit's dep-info records, and not by their modification times, which a checkout or a cache restore
resets: `.cargo/config.toml` sets `[unstable] checksum-freshness` and `[build] fingerprint =
"content"`, which the nightly toolchain needs together. A unit `-Z build-std` compiles is judged as
[§ Build Output: the Sysroot](#build-output-the-sysroot) describes. A build script's
`rerun-if-changed` files are still judged by time, and a script that reruns makes its package and
every dependent rebuild, so no package of the tree has a build script (a host test checks it): the
linker scripts of the kernel and of the riscv64 bootloader are passed by `cargo xtask build`
([§ Custom Targets](#custom-targets)). The toolchain's library build scripts
(`compiler_builtins`') name library sources, which are dated as below.

So the `build` jobs and `host-tests` carry their build between runs, through the composite action
`.github/actions/carry/action.yml`, restored before their first build and saved as their last
step. Its entry is `target/` but `target/xtask/`, which holds the job's signing identity and
records: Cargo's build directories, the `xtask` binary, and the toolchain mirror of the builds of
`std`, whose stamp and modification times it keeps, so the mirror is not rewritten while its
inputs are unchanged. The key is
`carry-<entry>-<ImageOS>-<ImageVersion>-<toolchain>-<config>-<commit>`: the job's entry
(`build-<arch>-<profile>` for the `build` job of one architecture and profile, or `host-tests`),
the runner image, whose libraries the entry's host build scripts and tools link against, the first
16 hex digits of the SHA-256 of `rustc -Vv`, those of the `hashFiles` digest of the inputs of
every unit that the checksums do not cover (the target specs, `.cargo/config.toml`, the action and
`xtask/wrapper-shim/`, which adds arguments to every rustc and clippy-driver command line of a
build through the toolchain mirror that Cargo never sees, Markdown excepted), and the commit. A
change to any file the key hashes owes every job that saves an entry, and the key hashes no other
source file of the tree, as host tests check. A job restores the
newest entry whose key starts with its own up to the commit: an entry built from another tree is
safe, since every unit restored is judged by the content of the tree it is restored into (a
`-Z build-std` unit through the mirror's stamp and the digest of the crates `std` depends on), and
only what differs is rebuilt. Before the
build it dates the toolchain's library sources to 2000-01-01, which the install writes with its own
time; the date hides no change, since the toolchain's version is in the key and in every unit's
fingerprint. Only a push run on `master` saves, after its uploads, under the commit, and then
deletes `master`'s other entries of the same key prefix, which no run would restore (the jobs
have `actions: write` for it); a pull request reads the entries its base made and never writes
one, so it evicts none of them.

The `build`, `burnin` and `build-image` jobs each have a step that sets
`SERAPH_SIGNING_DIR=$RUNNER_TEMP/seraph-signing`, so each job generates its signing keys outside
the checkout on its first build; `burnin` and `build-image` discard them with the job, and a
`build` job ships them to the cells of its run with its tree
([signing.md § Signing](signing.md#signing)).

`build-test.yml`'s `build` job carries its tree to the cells that boot it through the composite
action `.github/actions/tree/action.yml`. In `ship` mode, after the build, it packs into zstd tar
archives, which keep the modification times and modes an artifact's zip would lose, the sysroot,
the symbols store, `target/xtask/signing/`, the `xtask` binary and the job's signing identity, and
uploads them as the artifact `tree-<arch>-<profile>`; and the bootloader's build state
(`target/<boot triple>/` and the host's `target/<profile>/build/`, the state a lane of the cell
copies, [xtask/README.md § Cells](../xtask/README.md#cells)) as `tree-<arch>-<profile>-boot`. A
release job owing the `bench` cell then ships the bench-only image as `tree-<arch>-bench`. Each
artifact is kept three days, so a cell re-run after its build job still finds its tree. In `fetch`
mode, each cell downloads its tree, the usertest cell also the bootloader's build state, unpacks
them, puts the `xtask` binary on the `PATH` and points `SERAPH_SIGNING_DIR` at the identity;
with the bootloader's build state, it dates the toolchain's library sources as the build job did.
The usertest cell's `signing` and `rollback` cases, which compile bootloaders under trust stores
they generate, then recompile only the bootloader: Cargo judges the shipped units by content, so
the checkout's own times make none stale. That cell alone installs the toolchain (with `rust-src`
and `llvm-tools`), and the `bench` cell installs it with no component for the compiler version
`bench-check` records; no other cell has one.

The `build-image` job of `release.yml` boots nothing (its one `cargo xtask`
command is `build`), so it installs no QEMU and runs on `ubuntu-latest`.

`build-test.yml` cancels a pull request's stacked runs on the same ref;
every other run, each push to `master` among them, is grouped by its commit
and never cancelled, so each merge commit gets its own run
([conventions.md](conventions.md#ci-gating) § CI Gating). `burnin.yml`, `fuzz.yml` and
`release.yml` do not cancel on the same ref — a tag-push run completes even if a later tag
pushes, and a campaign completes even if another is dispatched.

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
