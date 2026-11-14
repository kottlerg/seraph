# xtask

Build task runner for Seraph, invoked as `cargo xtask <command>`.

---

## Source Layout

```
xtask/
├── Cargo.toml
├── clippy.toml                 # Clippy settings; frame threshold of a host thread's stack
├── README.md
├── baselines/
│   └── ktest-timing/           # Checked-in ktest timing baselines (see ktest-timing)
├── src/
│   ├── main.rs                 # Entry point; dispatches CliCommand
│   ├── cli.rs                  # Clap derive structs for every subcommand
│   ├── context.rs              # Resolved workspace and build-output paths
│   ├── crash_log.rs            # Symbolized crash reports from a serial log (symbolize --log)
│   ├── debug_stub.rs           # GDB stub staging (--debug-target, test-gdb)
│   ├── diag.rs                 # Diagnostics of the pull-request, record, and Issue checks
│   ├── arch.rs                 # Supported architectures and per-arch constants
│   ├── accel.rs                # Per-host QEMU acceleration-backend selection
│   ├── bundle.rs               # Bootloader bundle composition (MODULES table)
│   ├── disk.rs                 # GPT disk-image construction from the sysroot
│   ├── firmware.rs             # Host-side discovery of QEMU pflash firmware
│   ├── fs_compat.rs            # Portable file-materialisation helpers
│   ├── gh.rs                   # GitHub CLI wrappers for the pull-request and Issue commands
│   ├── host_lock.rs            # Host launch rules: the lock, the load check, admission
│   ├── qemu.rs                 # Shared QEMU argv construction
│   ├── qmp.rs                  # Minimal QMP client for the QMP-driven tests
│   ├── rust_src.rs             # In-project toolchain sysroot with the ruststd overlay
│   ├── stack_sizes.rs          # The riscv64 kernel frame check over `.stack_sizes`
│   ├── symbolize.rs            # ELF address resolution: DWARF, symbol-table fallback
│   ├── tasklist.rs             # GitHub task-list items, as the PR and Issue checks read them
│   ├── sysroot.rs              # Sysroot arch checks and the rootfs/ mirror
│   ├── timing.rs               # ktest log timing parser, reports, and baseline format
│   ├── util.rs                 # Step printing, command execution, tool lookup
│   ├── commands/               # Subcommand modules (build, run, run_parallel,
│   │                           #   ktest_timing, symbolize, mkdisk, compose_bundle, clean,
│   │                           #   test, compare_images, test_crash_report, test_debug_port,
│   │                           #   test_gdb, test_kaslr, test_map_redo, test_terminal,
│   │                           #   test_vmgenid, lint_docs, pr_check, review, release_scope,
│   │                           #   issue, orch, hook, host)
│   └── term/                   # Host-terminal adapters for the QEMU launch pipeline
├── targets/                    # Custom target JSON specs (see targets/README.md)
└── wrapper-shim/               # rustc / clippy-driver dispatch shim (see Sub-crates)
```

---

## Commands

### `cargo xtask build`

Build Seraph components and populate `sysroot/`.

```
cargo xtask build [--arch x86_64|riscv64] [--release] \
    [--component <name>|all] [--debug <comp>[,...]]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--release` | off | Build in release mode |
| `--component` | `all` | Build a single component: `boot`, the crate name of any component the build installs (an entry of the `SPECS` table in `xtask/src/commands/build.rs`: `kernel`, `init`, `ktest`, each service, driver, program, fixture, and tester crate), or `all` |
| `--debug` | (none) | Emit debuginfo (`debug=2`, `opt-level=1`) for the named component(s) only, each named as `--component` names it, e.g. `--debug kernel,crashme`; applies within the active profile. See [Build Profiles](../docs/build-system.md#build-profiles). |

The sysroot is architecture-specific. Building for a different arch than the
existing sysroot is an error — run `cargo xtask clean` first (per
[docs/build-system.md](../docs/build-system.md) § Build Output: the Sysroot).

Every cargo command of the build runs with `CARGO_INCREMENTAL=0`, as CI's jobs build, so a local
build of a commit orders its binaries' statics as CI's does (see
[Build Profiles](../docs/build-system.md#build-profiles)); its addresses can still be offset from
CI's ([docs/testing.md](../docs/testing.md#troubleshooting) § Troubleshooting).

A riscv64 kernel build runs with `RUSTFLAGS="-Zunstable-options -Zemit-stack-sizes"`, which
reaches the `-Z build-std` crates as well, and its Clippy pass with the same flags. After the link,
and before the image is installed, the build reads the image's `.stack_sizes` section and fails,
naming each function and its frame, when a frame passes `RISCV64_KERNEL_FRAME_MAX` (2032 bytes,
`src/stack_sizes.rs`), the kernel frame bound of
[docs/coding-standards.md](../docs/coding-standards.md) § Kernel Stack Frames. It fails as well
when the image has no such section. No other build has the check.

---

### `cargo xtask run`

Launch Seraph under QEMU. `run` is a pure runner — it does not build.
Run `cargo xtask build` first; `run` errors fast if the sysroot is empty
or stamped for a different architecture.

```
cargo xtask run [--arch x86_64|riscv64] [--gdb] [--headless] [--verbose] \
    [--cpus N] [--mem MIB] [--riscv-mmu sv39|sv48|sv57] [--x86-paging 4|5] \
    [--iommu attached|absent] \
    [--second-disk PATH [--second-disk-block-size BYTES] [--second-disk-shared-line]] \
    [--debug-port PORT [--debug-target NAME]] [--test-devices]
```

| Option | Description |
|---|---|
| `--arch` | Target architecture (default: `x86_64`) |
| `--gdb` | Start QEMU with a GDB server on localhost:1234; QEMU pauses at startup. Userspace binaries are PIE with a per-spawn randomized base (ASLR, #39; see [docs/userspace-memory-model.md](../docs/userspace-memory-model.md) § Image Placement): take the bias from the creator's log line (procmgr `spawn image bias=0x…`, init `init: <svc> image bias=0x…`, kernel `init: PIE bias=0x…`) and load symbols with `add-symbol-file <binary> -o <bias>` |
| `--headless` | Run without a display window (`-display none`) |
| `--verbose` | Show all serial output; by default output is filtered until `[--------] boot:` appears |
| `--cpus` | Number of vCPUs to expose to the guest (default: `4`; bounded by `1..=8192`, `boot_protocol::MAX_CPUS`, the boot protocol's CPU ceiling) |
| `--mem` | Guest memory size in MiB (default: `512`) |
| `--riscv-mmu` | Guest RISC-V paging-mode ceiling (default: `sv48`; riscv64 only, ignored on x86_64). Sets the QEMU `svNN` CPU properties, which cap the `satp` modes the CPU implements (and the DTB `mmu-type` QEMU authors); the bootloader takes the DTB `mmu-type` as the candidate (Sv57 when the firmware publishes no DTB, as under EDK2) and confirms it with a `satp` write-probe that falls back to the next-narrower mode ([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § Mode negotiation), and the kernel recovers the active mode from `satp`, per [docs/memory-model.md](../docs/memory-model.md) § RISC-V (Sv39 / Sv48 / Sv57). The default pins `sv48` because QEMU ≥ 8.0 otherwise defaults the rv64 CPU to `sv57` |
| `--x86-paging` | Guest x86-64 paging depth (default: `4`; x86_64 only, ignored on riscv64). Appends `la57=off` (`4`) or `la57=on` (`5`) to the QEMU `-cpu` model on every accelerator, which sets the CPUID LA57 bit the bootloader negotiates the depth from ([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § x86-64: Negotiated Paging Depth); the kernel recovers the depth from `CR4.LA57`, per [docs/memory-model.md](../docs/memory-model.md) § x86-64. The default pins `4` because TCG's `-cpu max` otherwise advertises LA57. `5` on a native accelerator (KVM, HVF, WHPX, NVMM) whose host CPU lacks LA57 fails before launch, naming the TCG route (`SERAPH_ACCEL=tcg`), since QEMU would drop the property with a warning and boot 4-level |
| `--iommu` | Whether the machine's IOMMU is attached (default: `attached`): `intel-iommu` with interrupt remapping and 32-bit destinations offered (`intremap=on,eim=on`, under KVM on a `kernel-irqchip=split` machine) on x86-64, `riscv-iommu-pci` in Bare mode (`off=off`) at 00:01.0 on riscv64, with the `virtio-pci` devices a driver of the system binds behind it (`iommu_platform=on`). `absent` boots the no-IOMMU variant, the no-iommu device cell of the local and release host runs ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers), which keeps devmgr's unconfined path covered while the attached IOMMU confines every device a driver binds, on both architectures ([docs/device-management.md](../docs/device-management.md#dma-safety-model) § DMA Safety Model) |
| `--second-disk` | Attach `PATH` as a second disk: its own `virtio-blk-pci` device (drive `hd1`) beside `disk.img`, presenting the logical block size of its GPT (see Attached devices). `mkdisk --split-data` authors `disk-data.img` for it; any GPT image at 512- or 4096-byte blocks serves too, and any other image needs `--second-disk-block-size` |
| `--second-disk-block-size` | Logical and physical block size, in bytes, of the second disk's device, overriding the size read from its image: a power of two of at least 512, up to QEMU's own limit. A size above virtio-blk's `MAX_BLOCK_SIZE` (4096), such as `8192`, stages the refused second disk of the disk variations ([docs/testing.md](../docs/testing.md) § Coverage tiers) |
| `--second-disk-shared-line` | Place the second disk's device on the first disk's `INTx` line instead of a line of its own, and launch both disks with no MSI-X (see Attached devices), staging the boot in which two virtio-blk devices share one line. Requires `--second-disk` |
| `--debug-port` | Attach the debug port (see Attached devices): a `virtio-serial-pci` device with one `virtconsole` port, which devmgr binds as the debug port ([services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md)), its host end a TCP server on `127.0.0.1:PORT` that does not wait for a client. A host debugger connects with `target remote localhost:PORT`. The console keeps the UART on `-serial stdio` |
| `--debug-target` | Stage the GDB stub ([services/gdbstub/README.md](../services/gdbstub/README.md)) for this boot, attached to the process whose `argv[0]` is `NAME` (for a service, the first word of its recipe's `argv`): write the stub's template from `config/svcmgr/debug/` into `config/svcmgr/services/` with `NAME` appended to its `argv`, repack the disk images in the layout they have (`disk.img`'s block size, and `disk-data.img` when it is there), and print the host GDB command line, with the process's sysroot binary for symbols when a staged recipe or `programs/`/`services/` names it; the stub reports the load bias, so GDB relocates the symbols itself. `NAME` is one word of at most 64 bytes, procmgr's name length. The stub is removed and the images repacked in that layout when QEMU exits; a `run` interrupted before that leaves it staged until a `build` or a full `mkdisk` reinstalls the sysroot's recipes, or the next `run --debug-target`; `mkdisk --repack-only` keeps it. Requires `--debug-port` |
| `--test-devices` | Attach the test devices (see Attached devices): `edu` and four `pci-testdev` functions, which svctest's devmgr phases drive and which no other launch attaches. svctest fails, naming this flag, when they are missing. The svctest boot also needs the test class files staged ([docs/testing.md](../docs/testing.md#gating) § Gating) |

**x86-64** selects an acceleration backend per host: KVM on Linux,
HVF on macOS, WHPX on Windows, NVMM on NetBSD, or TCG everywhere else
(see `SERAPH_ACCEL` below to override). KVM/HVF hosts must advertise
x86-64-v3 (AVX2/BMI2/FMA — Haswell+ / Excavator+) because the userspace
target is pinned to that psABI level
([docs/build-system.md](../docs/build-system.md) § Custom Targets); TCG mode uses
`-cpu max,migratable=no` which emulates the same baseline. Requires
OVMF firmware (`dnf install edk2-ovmf` / `apt install ovmf` /
`pacman -S edk2-ovmf` / Homebrew `brew install qemu` /
FreeBSD `pkg install edk2-qemu-x64`).

**RISC-V** always uses TCG with edk2 UEFI firmware and OpenSBI (loaded
automatically by QEMU's `virt` machine). Requires edk2 RISC-V firmware
(`dnf install edk2-riscv64` / `apt install qemu-efi-riscv64`) and
QEMU ≥ 9.0 (the V extension, and the `ssaia`/`smaia` CPU properties). `xtask`
passes the explicit feature string, and `-machine virt,aia=aplic-imsic`, on
every riscv64 QEMU launch and every supported QEMU; the named `-cpu rva23s64` model
is a superset that `xtask` does not expose (see
[docs/build-system.md](../docs/build-system.md) § QEMU and Firmware).

#### Attached devices

Every `run` attaches, on both architectures, the disk image as `virtio-blk-pci` (drive `hd0`), a
`virtio-keyboard-pci` keyboard (`id=kbd0`, the device `test-terminal` injects keys into over QMP), a
`virtio-rng-pci` boot-entropy source, the guest UART on `-serial stdio`, and, unless `--iommu
absent`, the machine's IOMMU: `intel-iommu,intremap=on,eim=on` on x86-64, whose interrupt remapping
makes a KVM launch's machine `q35,kernel-irqchip=split`, and `riscv-iommu-pci` in Bare mode on
riscv64, with the disks and the keyboard behind it (`iommu_platform=on`); the RNG, which only the
firmware drives, stays outside it. The riscv64 IOMMU is the first device of the command line, pinned
at 00:01.0, so every auto-placed device takes a slot above it: QEMU's ACPI RIMT describes the IOMMU
as translating only the requester IDs above its own. `--test-devices` adds, on both architectures,
`-device edu,dma_mask=0xffffffff`, QEMU's DMA test device (PCI `1234:11e8`) with a 32-bit DMA mask
so its engine reaches the interrupt addresses the forged-message phase writes, behind the IOMMU
when one is attached, which only svctest's DMA confinement and MSI phases drive
([services/drivers/test-dma/README.md](../services/drivers/test-dma/README.md)), and four QEMU
`pci-testdev` functions (PCI `1b36:0005`) at pinned slots 0x15, 0x16, 0x17 (`membar=4K`) and 0x18
(`membar=8K`), which the test-only `test-fault` driver binds
([services/drivers/test-fault/README.md](../services/drivers/test-fault/README.md)). No other launch
attaches them, and no production driver binds them. On x86-64 a launch also attaches `-device
vmgenid,guid=auto`, the VMGENID generation-ID device
([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Whole-VM-snapshot detection
(VMGENID)); QEMU's riscv64 `virt` machine has no VMGENID. A non-headless run adds QEMU std VGA: the
q35 default adapter on x86-64, and on riscv64 `-device VGA` with a `qemu-xhci`/`usb-kbd` pair, added
only when a `gtk` or `sdl` display backend is available. `--headless` drops the display adapter, so
no framebuffer is advertised. `run-parallel --display framebuffer` keeps the adapter with no display
window (`-display none`): the q35 default adapter on x86-64 and `-device VGA` alone on riscv64,
whatever display backends QEMU has. `--debug-port` adds a `virtio-serial-pci` device, behind the
IOMMU when one is attached, carrying one `virtconsole` port on the character device `seraph-debug`,
a TCP server on `127.0.0.1` at the given port (`server=on,wait=off`).

The disk device presents the logical block size of the image it boots, 512 or 4096 bytes
(`logical_block_size` and `physical_block_size`), read from the LBA its GPT header sits at, so a
4Kn image from `mkdisk --block-size 4096` boots as a 4Kn disk with no launch option; every
launcher (`run`, `run-parallel`, and the `test-*` runners) does the same. `run` and
`run-parallel` attach `--second-disk` as a second `virtio-blk-pci` device on drive `hd1`, at its
own image's block size unless `--second-disk-block-size` sets it. A two-disk launch pins the
disks to PCI slots `0x10` and `0x12`, which OVMF (x86-64) and the `virt` host bridge (riscv64)
route to distinct `INTx` lines, so each disk has a line of its own. With
`--second-disk-shared-line` the second disk sits at slot `0x14` instead, which both machines route
to the first disk's line, and both disks are launched with `vectors=0`, so they present no MSI-X
capability and devmgr gives their driver the line they share
([docs/device-management.md](../docs/device-management.md) § Interrupt Delivery). OVMF routes
every x86-64 PCI slot to one of two lines, so in a two-disk x86-64 boot the keyboard shares a
line with a disk.

#### Environment variables

These override `cargo xtask run`'s built-in firmware and accelerator
selection. None are required when the host follows FHS conventions
and the distro ships standard firmware packages.

| Var | Effect |
|---|---|
| `SERAPH_OVMF_CODE` | Direct path to the OVMF code firmware. Skips the per-platform default search. |
| `SERAPH_RISCV_CODE` | Direct path to `RISCV_VIRT_CODE.fd`. Must be set together with `SERAPH_RISCV_VARS` — partial overrides are rejected (a custom code image paired against the system vars template corrupts NVRAM state). |
| `SERAPH_RISCV_VARS` | Direct path to `RISCV_VIRT_VARS.fd`. See pairing rule above. |
| `SERAPH_ACCEL` | One of `auto` / `tcg` / `kvm` / `hvf` / `whpx` / `nvmm`. `auto` (the default) runs per-host detection. Cross-arch guests (e.g. riscv64 on x86) always resolve to `tcg`; an explicit non-`tcg`/`auto` override in that case emits a stderr warning. Unrecognized values also warn and fall through to detection. |

Default firmware search paths per host:

- **Linux** OVMF: `/usr/share/edk2/ovmf/OVMF_CODE.fd`, `/usr/share/OVMF/OVMF_CODE.fd`,
  `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd`, `/usr/share/ovmf/OVMF.fd`,
  `/usr/share/edk2/x64/OVMF_CODE.4m.fd`
- **Linux** RISC-V: `/usr/share/edk2/riscv`, `/usr/share/edk2-riscv`, `/usr/share/qemu-efi-riscv64`
- **macOS** (both): `/opt/homebrew/share/qemu`, `/usr/local/share/qemu`
- **BSD** (both): `/usr/local/share/qemu`, `/usr/local/share/uefi-firmware`
- **Windows / other**: no defaults; the relevant `SERAPH_*` env var is required.

---

### `cargo xtask mkdisk`

Re-mirror `rootfs/` into `sysroot/`, re-synthesise test fixtures, and
regenerate `disk.img` without invoking cargo. Use after editing
`rootfs/` to refresh the boot image without paying for a full
`cargo xtask build` (which would also run cargo fmt + clippy + check +
binary install). Requires a populated, arch-tagged sysroot from a prior
`cargo xtask build`.

The mirror is authoritative over the rootfs-managed subtrees (`config/`,
`data/`): files deleted from `rootfs/` are pruned from the sysroot, while
build-owned trees (`esp/`, `services/`, `programs/`, `tests/`) and the
synthesised `data/svctest/` fixtures are left untouched. To pack a
hand-staged sysroot that diverges from `rootfs/` — e.g. a test recipe
copied from `sysroot/config/svcmgr/tests/` into
`sysroot/config/svcmgr/services/` — use `--repack-only`, which skips the
re-mirror and packs the sysroot exactly as it stands (a plain repack would
prune the hand-added recipe). The mirror rules are owned by
[rootfs/README.md](../rootfs/README.md).

`mkdisk` does **not** author `sysroot/EFI/seraph/bootstrap.bundle` — it
fails if the bundle is missing. The bundle is composed by
`cargo xtask build` (default-init) or by
[`cargo xtask compose-bundle`](#cargo-xtask-compose-bundle) (any
harness). `mkdisk` always removes the `\EFI\seraph\mapredo` test knob, which
only [`test-map-redo`](#cargo-xtask-test-map-redo) stages, for its own boot.

`disk.img` carries three GPT partitions: the EFI System Partition
(from `sysroot/esp/`), the arch-specific Seraph root (from `sysroot/`,
excluding `esp/` and `data/`), and an arch-neutral `SERAPH_DATA`
partition (from `sysroot/data/`). The data partition is authored
unconditionally; `mkdisk --split-data` authors it alone on a second image,
`disk-data.img` beside `disk.img`, which then carries the other two, for a
boot that attaches the pair (`run --second-disk disk-data.img`), and every
other authoring removes a `disk-data.img` left beside it. vfsd auto-mounts
the data partition at `/data`, on whichever disk holds it; the data tree
lives only on this partition, not on root.
(vfsd's fall-through would also serve `/data` from a root-fs directory,
so a dedicated partition is a disk-authoring choice — the in-tree image
uses the partition, per [docs/storage.md](../docs/storage.md) § GPT Role-GUID Discovery.)
The images' logical block size, the unit of their GPT LBAs and the sector
size of their FAT volumes, is 512 bytes, or 4096 bytes (4Kn) from
`mkdisk --block-size 4096`. `build`, `mkdisk`, and `compose-bundle` all
author the partitions above; `build` and `compose-bundle` author them at 512 bytes on a single
image, so a 4Kn or split boot runs `mkdisk` after them. `run --debug-target`,
`run-parallel --debug-target`, `test-gdb`, `test-debug-port`, `test-kaslr`, and `test-map-redo`
repack the images in the layout they find: `disk.img`'s block size, and the data partition on
`disk-data.img` when that image is there. The four test commands boot that layout, attaching
`disk-data.img` as the second disk when it holds the data partition; `run` and `run-parallel`
attach a second disk only as `--second-disk` names it.

```
cargo xtask mkdisk [--arch x86_64|riscv64] [--repack-only] [--no-kaslr] \
    [--block-size 512|4096] [--split-data]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture — must match the existing sysroot's arch tag |
| `--repack-only` | `false` | Skip the `rootfs/` re-mirror and pack the sysroot as it stands — preserves a hand-staged service set the authoritative mirror would otherwise reconcile |
| `--no-kaslr` | `false` | Stage the `\EFI\seraph\nokaslr` override knob so the bootloader boots the kernel at its deterministic (un-randomized) layout ([core/boot/docs/boot-flow.md](../core/boot/docs/boot-flow.md) § Step 5d: Apply the KASLR Slide), for GDB / symbolization; omit to remove the knob and re-enable KASLR |
| `--block-size` | `512` | Logical block size of the authored images: `4096` writes the GPT at 4096-byte LBAs and formats every FAT volume with 4096-byte sectors (a 4Kn disk) |
| `--split-data` | `false` | Author the data partition alone on `disk-data.img` and the ESP and root on `disk.img`, both at `--block-size`; omit to author all three on `disk.img` and remove a stale `disk-data.img` |

Example — stage `svctest` and run it (`--repack-only` keeps the hand-added
recipe; a plain repack would prune it):

```sh
cp sysroot/config/svcmgr/tests/svctest.svc sysroot/config/svcmgr/services/
cp sysroot/config/devmgr/tests/*.class sysroot/config/devmgr/classes/
cargo xtask mkdisk --repack-only --arch x86_64
cargo xtask run --arch x86_64 --test-devices
```

Example — boot the staged svctest set from a 4Kn disk, then with the data
partition on a second disk:

```sh
cargo xtask mkdisk --repack-only --block-size 4096
cargo xtask run --arch x86_64
cargo xtask mkdisk --repack-only --split-data
cargo xtask run --arch x86_64 --second-disk disk-data.img
```

See [docs/testing.md](../docs/testing.md) for the test-harness gating
contract.

---

### `cargo xtask compose-bundle`

Compose `sysroot/esp/EFI/seraph/bootstrap.bundle` from canonical
binaries under `sysroot/services/` and repack `disk.img`. Symmetric
with `mkdisk`: both end with `create_disk_image`, the difference being
which file they author. `compose-bundle` is the bundle authoring step;
`mkdisk` never authors the bundle.

```
cargo xtask compose-bundle [--arch x86_64|riscv64] [--harness init|ktest]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture — must match the existing sysroot's arch tag |
| `--harness` | `init` | Which binary becomes the bundle's `init` entry: `init` for the regular userspace init, `ktest` for the kernel-test harness |

`--harness init` produces a 10-entry bundle on x86-64 and an 11-entry bundle on
riscv64 (`init` + the 8 boot modules listed in `xtask/src/bundle.rs::MODULES`, the IOMMU
driver of the architecture's family from `ARCH_MODULES`, `iommu-vtd` on
x86-64 and `iommu-riscv` on riscv64, and, on riscv64, the platform description table
`platform-qemu-virt` from `ARCH_TABLES`; the bootloader and init address entries
by name, so order is not significant). `--harness ktest`
produces a single-entry bundle (`ktest` as the `init` entry, zero
modules); ktest is monolithic and does not spawn userspace.

Both `cargo xtask build` and `compose-bundle` are *authoring* steps —
both deliberately overwrite the bundle. `mkdisk` is the
refresh-from-sysroot path and never authors.

Example — switch to ktest, run, then switch back to regular init:

```sh
cargo xtask compose-bundle --arch x86_64 --harness ktest
cargo xtask run --arch x86_64 --headless

# Reset to default-init for the next boot:
cargo xtask compose-bundle --arch x86_64 --harness init
cargo xtask run --arch x86_64
```

ktest's runtime options (`shutdown_policy`, `timeout_secs`, filter
tiers, bench iteration count) bake in as compile-time defaults in
`core/ktest/src/cmdline.rs::KtestConfig::DEFAULT` (CI-friendly:
shutdown=Always, timeout=0, full filter, 1000 bench iters). To change
them, edit the constant, run `cargo xtask build --component ktest`, then
re-compose with `cargo xtask compose-bundle --harness ktest` (a
single-component build does not re-compose the bundle); see
[core/ktest/README.md](../core/ktest/README.md) § Compile-time options.

---

### `cargo xtask clean`

Remove the sysroot and the disk images `disk.img` and `disk-data.img` (and optionally
`target/`).

```
cargo xtask clean [--all]
```

| Option | Description |
|---|---|
| `--all` | Also run `cargo clean` to remove the `target/` directory |

---

### `cargo xtask test`

Lint the test code, then run Seraph unit tests on the host target and under riscv64 emulation.

```
cargo xtask test [--component boot|protocol|kernel|init|all]
```

The lint pass runs `cargo clippy --tests` over the selected packages, once for
`x86_64-unknown-linux-gnu` and once for `riscv64gc-unknown-linux-gnu`, with all warnings treated as
errors, so test code gated on either architecture is linted on any host. Each pass only checks: it
builds `std` from source for its target (`-Zbuild-std=std,panic_unwind,test`), needs no rustup
target, and links nothing. It allows the lints `TEST_RELAXED_LINTS` in `src/commands/test.rs`
names, as [docs/coding-standards.md](../docs/coding-standards.md) § Clippy states.

Tests compile for the host — no `--arch` flag needed. The workspace-level
`panic=abort` profile does not affect the test harness.

Then the tests of the selected packages, the host-only `xtask` and `seraph-wrapper-shim` left
out (`HOST_ONLY`), build for `riscv64gc-unknown-linux-gnu` with `std` from source, link with
`riscv64-linux-gnu-gcc`, and run under QEMU's user-mode emulator
(`qemu-riscv64 -L /usr/riscv64-linux-gnu`), so a test gated on riscv64 runs on an x86_64 host.
That build uses an unwinding `dev` profile (`CARGO_PROFILE_DEV_PANIC=unwind`), since the test
harness cannot link with a `std` built for `panic=abort`. The command fails, naming the packages
to install, when the emulator, the cross compiler or its C library is missing
([docs/build-system.md](../docs/build-system.md) § Toolchain).

The command is admitted as a build under the [Host launch rules](#host-launch-rules), and takes
their `--wait-host` and `--host-override` options.

---

### `cargo xtask compare-images`

Build two commits for each architecture and profile, and compare every file the build installs in
the parts a loader reads: the evidence for the Identical images class of
[docs/testing.md](../docs/testing.md) § Coverage tiers, Inert changes.

```
cargo xtask compare-images [--base REV] [--head REV] [--arch x86_64|riscv64]... \
    [--profile debug|release]...
```

| Option | Default | Description |
|---|---|---|
| `--base` | `git merge-base <head> origin/master` | The base commit: by default the base of the PR's own diff |
| `--head` | `HEAD` | The head commit |
| `--arch` | both | The architectures to build; repeatable, or comma-separated |
| `--profile` | both | The profiles to build; repeatable, or comma-separated |

Both commits are built in one scratch worktree, which the command adds with
`git worktree add --detach` and reuses: it checks each commit out there, removes every untracked
file but `target/`, and runs that commit's own `cargo xtask clean` and
`cargo xtask build --skip-lints --arch <a> [--release]` once per cell, moving each built sysroot to
`target/xtask/compare-images/<base|head>/<arch>-<profile>/`. One path serves both commits because a
build embeds absolute source paths (the panic locations of the `-Z build-std` crates under
`target/seraph-toolchain/`), so builds in two checkouts never compare equal. The scratch
worktree's `target/` is kept as a cache, so a later comparison rebuilds only what changed; the
first one builds every cell from scratch.

Each build is the commit's own. The scratch worktree is
`<cache>/seraph-compare-images/<checkout path, each other character as ->`, `<cache>` being
`XDG_CACHE_HOME`, else `~/.cache`: outside the checkout, whose `.cargo/config.toml` Cargo would
merge into every build below it. The command refuses to run when a directory above the scratch
worktree holds a Cargo configuration other than Cargo's home's. Each nested `cargo xtask` runs
without the variables the outer `cargo run` and the rustup proxy set: `CARGO` and each `CARGO_*`
but `CARGO_HOME`, `RUSTUP_TOOLCHAIN` (which outranks the commit's `rust-toolchain.toml`),
`RUST_RECURSION_COUNT`, and each variable set by the `[env]` table of a Cargo configuration the
outer build read (the checkout's and those above it, and Cargo's home's), such as
`RUST_TARGET_PATH`, which names the commit's target specifications.
`cargo xtask clean --all` leaves the scratch worktree; `git worktree remove --force <path>`
removes it.

Each file of a cell's two sysroots is compared by its format:

| File | Compared parts |
|---|---|
| ELF image | The type, machine, flags, and entry of the file header; each program header but its file offset, with the bytes of each `PT_LOAD` segment past the file header (whose section-table fields locate data no loader maps); each section that is allocated or is a note, its type, flags, address, size, and bytes, since the loaders read `.note.seraph.*` sections by name |
| PE image (`boot.efi`) | The headers, the COFF link time stamp and the checksum masked; each section, the debug directory and the data its entries point to masked: the linker writes the time of the link there, and no UEFI loader and no code of the image reads them |
| The bootloader bundle | Its header, its entry names in order, and each entry's parts as an image, named `entry <name>: <part>`; an entry's offset and size move with bytes no loader maps and are not compared |
| Any other file, or an image whose headers do not parse | Its bytes, as the part `contents` |

A file in one sysroot only is reported as `added` or `removed`. The symbol tables, the debug
information, `.comment`, and a file's size are not compared. The disk image is not compared
either: `xtask/src/disk.rs` packs it from the compared files, and a change to that code is under
`xtask/`, whose lines, and those of the crates xtask's build compiles in, the class leaves to the
coverage screens.

The command prints, for each cell, its file count and each difference as `<path>: <part>`, then
the verdict line, and writes the same text to
`target/xtask/compare-images/report-<base>-<head>.txt`, each commit by its first 12 hex digits:

```
compare-images: IDENTICAL base <sha> head <sha> cells <arch>-<profile>,...
```

The cells are listed in the order built:
`x86_64-debug,x86_64-release,riscv64-debug,riscv64-release` for a run of all four. The verdict is
`DIFFERENT (<count>)` when any part differs, and the command then fails. The command is admitted
as a build under the [Host launch rules](#host-launch-rules), and passes its `--wait-host` on to
each build and clean it runs, which are admitted on their own.

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
    [--mem MIB] \
    [--riscv-mmu sv39|sv48|sv57] \
    [--x86-paging 4|5] \
    [--iommu attached|absent] \
    [--display headless|framebuffer] \
    [--second-disk PATH [--second-disk-block-size BYTES] [--second-disk-shared-line]] \
    [--debug-port PORT [--debug-target NAME]] \
    [--test-devices] \
    [--pass REGEX] \
    [--fail REGEX] \
    [--fail-also REGEX] \
    [--fail-grace-secs SECONDS] \
    [--debug-listen] \
    [--hold-on-hang] \
    [--save-logs DIR]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--parallel` | (required) | Concurrency: QEMU instances in flight at once |
| `--runs` | (required) | Total runs, dispatched in waves of `--parallel` |
| `--timeout` | `30` | Per-run timeout in seconds; expired runs are SIGKILLed and classified `HANG` (unless a pass marker matched first) |
| `--cpus` | `4` | vCPUs per guest (bounded by `1..=8192`, `boot_protocol::MAX_CPUS`) |
| `--mem` | `512` | Guest memory size in MiB |
| `--riscv-mmu` | `sv48` | Guest RISC-V paging-mode ceiling (riscv64 only, ignored on x86_64); same semantics as `cargo xtask run --riscv-mmu` |
| `--x86-paging` | `4` | Guest x86-64 paging depth (x86_64 only, ignored on riscv64); same semantics as `cargo xtask run --x86-paging` |
| `--iommu` | `attached` | Whether the machine's IOMMU is attached; same semantics as `cargo xtask run --iommu` |
| `--display` | `headless` | What each guest presents for display, never a window. `headless` drops the display adapter, as `cargo xtask run --headless` does, so devmgr spawns no framebuffer driver. `framebuffer` keeps QEMU std VGA (see Attached devices) with no display window (`-display none`), on a host with or without a graphical backend, so the bootloader hands the kernel a GOP framebuffer and devmgr spawns the framebuffer driver: the framebuffer device cell ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers) |
| `--second-disk` | (none) | Attach `PATH` as a second disk, as `cargo xtask run --second-disk` does; each slot boots its own copy, as it does of `disk.img` |
| `--second-disk-block-size` | (the image's) | Block size of the second disk's device; same semantics as `cargo xtask run --second-disk-block-size` |
| `--second-disk-shared-line` | off | Place the second disk on the first disk's `INTx` line; same semantics as `cargo xtask run --second-disk-shared-line` |
| `--debug-port` | (none) | Attach the debug port, served on `127.0.0.1:PORT`; same semantics as `cargo xtask run --debug-port`. Requires `--parallel 1` (one host port) |
| `--debug-target` | (none) | Stage the GDB stub for these boots, attached to the process named `NAME`, and print the host GDB command line; same semantics as `cargo xtask run --debug-target`. The stub is staged, and the images repacked in the layout they have, before the runs copy them, and removed after the last run. Requires `--debug-port` |
| `--test-devices` | off | Attach the test devices to each guest; same semantics as `cargo xtask run --test-devices` |
| `--pass` | `ALL TESTS PASSED` | Regex marking a successful run. The default matches the cross-harness terminal marker `[<harness>] ALL TESTS PASSED` standardised in [docs/testing.md](../docs/testing.md). On match the log is discarded and the run is classified `PASS` |
| `--fail` | `SOME TESTS FAILED\|KERNEL EXCEPTION\|FATAL:\|PANIC( at \|: )\|=== WATCHDOG\|entropy: SELFTEST FAIL` | Regex marking a failed run; the **first** match wins, the log is preserved as `FAIL-<run>.log`, and failure takes precedence over success. The default's markers are explained below the table |
| `--fail-also` | (none) | A further regex marking a failed run, matched beside `--fail` rather than in its place, so the default's markers still apply: a log matching either is `FAIL`, at `--fail`'s precedence and with its `--fail-grace-secs` kill. The framebuffer device cell passes `'framebuffer case skipped'`, so a boot in which svctest's framebuffer case skips fails |
| `--fail-grace-secs` | `10` | After the first `--fail` match, wait this many seconds (bounded by `--timeout`) before SIGKILL, so the trailing fault dump still lands in the log. A crashed run thus aborts ~grace seconds after the first match instead of idling to `--timeout` |
| `--debug-listen` | off | Expose each guest's gdbstub without pausing it (QEMU `-s`, tcp::1234) so a wedged guest can be attached post-hoc: `gdb -ex 'target remote :1234'`. Requires `--parallel 1` (one gdbstub port) |
| `--hold-on-hang` | off | On a hard-timeout `HANG` (no `--fail` match), do not kill QEMU: print the attach instructions and block until the instance is terminated externally, preserving the wedged guest for a debugger. Pair with `--debug-listen`. Requires `--parallel 1` |
| `--save-logs` | off | Also copy every run's log, whatever its outcome, to `DIR/<arch>-<cpus>cpu-<run>.log`, with a trailer line `[run-parallel] arch=<a> cpus=<n> accel=<kvm\|tcg\|...> run=<r> outcome=<STATUS> wall_s=<secs>` appended. DIR is created if absent and never purged, and a file of the same name is overwritten. The copies are what `ktest-timing` reads |

The default `--fail` regex matches the cross-harness terminal marker
`[<harness>] SOME TESTS FAILED` ([docs/testing.md](../docs/testing.md)) plus the
kernel's own death markers: `KERNEL EXCEPTION` and `FATAL:` for a hardware trap,
`PANIC at` or `PANIC:` for a Rust `panic!`, `=== WATCHDOG` for a scheduler
wedge-detector dump, and `entropy: SELFTEST FAIL` for a kernel entropy self-test
failure ([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Testing), so a crash
classifies `FAIL` rather than `HANG`. The benign `USERSPACE FAULT` path matches none of these.
Override with a never-matching pattern (for example `'$.^'`) to disable.

**Mode-agnostic**: xtask does not know about ktest, svctest, or any other
rootfs configuration. Pass/fail markers come from the invoker. The default
`--pass` works for both modes because they emit the same terminal marker
([docs/testing.md](../docs/testing.md) § Reporting marker). Override for other
configurations:

```sh
# Default (works for ktest or svctest)
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100

# Custom marker
cargo xtask run-parallel --arch x86_64 --parallel 4 --runs 100 \
    --pass 'my-app: shutdown clean' --fail 'PANIC'
```

**Output**: one line per completed run, plus a summary block. Logs for
non-passing runs are preserved under `target/xtask/run-parallel/` as
`OK-<run>.log`, `FAIL-<run>.log`, `HANG-<run>.log`, `ERR-<run>.log`, or
`QEMU-CRASH-<run>.log`. PASS logs are discarded there (`--save-logs` keeps a copy of every
log elsewhere). Beside each log it keeps, in either place, whose log holds a crash-report block, a
run writes the block's symbolized report, `cargo xtask symbolize --log`'s output against the
current sysroot, as `<name>.crash.txt` for `<name>.log`, and removes a stale `<name>.crash.txt` of
a log without one; it symbolizes only for a run that keeps its log, and a failure writing the report
is a warning that changes no outcome. Each invocation first removes the run logs and crash reports
an earlier one left under `target/xtask/run-parallel/`, so the preserved files are its own.

**Outcome precedence**:
1. `--fail` regex matches → `FAIL` (a live match also triggers early abort
   after `--fail-grace-secs`, bounded by `--timeout`; the verdict is unchanged)
2. `--pass` regex matches → `PASS` (even if QEMU was watchdog-killed,
   which is the normal case for kernels that idle after success)
3. Watchdog timeout → `HANG`
4. Exit code 0 with no marker → `OK`
5. Killed by SIGSEGV/SIGABRT with no marker → `QEMU-CRASH` — the host emulator
   crashed, not the guest. Tallied in the summary and preserved as
   `QEMU-CRASH-<run>.log`, but does **not** fail the run (infrastructure flake,
   not a regression in the OS under test; the recurring case is the QEMU 8.2.x
   multi-threaded-TCG segfault,
   [QEMU gitlab #2220](https://gitlab.com/qemu-project/qemu/-/issues/2220)).
   SIGKILL is excluded (the `--timeout` kill, or an OOM).
6. Other exit code → `ERR rc=<n>` (a signal death is reported as `128 + signum`,
   e.g. `139` for SIGSEGV)

---

### `cargo xtask ktest-timing`

Read ktest boot logs saved by `run-parallel --save-logs` and report their wall times: the
measurement of the boundary runs of [docs/testing.md](../docs/testing.md) § Coverage tiers
(Timing report). Report-only: a flagged row never fails the command.

```
cargo xtask ktest-timing LOG...
cargo xtask ktest-timing --base LOG --wide LOG [--threshold R] [--min-secs S]
cargo xtask ktest-timing --baseline FILE LOG [--threshold R] [--min-secs S]
cargo xtask ktest-timing --write-baseline FILE [--commit REV] LOG
```

| Option | Default | Description |
|---|---|---|
| `LOG...` | | Print each log's table: its tiers, its cells in log order with their outcome, then the whole-run rows |
| `--base`, `--wide` | | Cross-width comparison of two logs of one architecture: per row the base and wide times, their ratio `R`, and `R/F` with `F` = wide CPUs / base CPUs |
| `--baseline` | | Same-width comparison of the one `LOG` with a baseline file of its architecture and width (refused otherwise): per row the baseline and log times and their ratio. A `WARNING:` line heads the report for each of the baseline's `host-cpu`, `host-kernel`, `qemu`, and `accel` values that differs from this host's |
| `--write-baseline` | | Write the one `LOG`'s timing to `FILE` in the format below |
| `--commit` | `HEAD` | The commit the `LOG` ran at, recorded by `--write-baseline` |
| `--threshold` | `1.5` | Flag a row whose normalised ratio (`R/F`, or the ratio to the baseline) exceeds this |
| `--min-secs` | `1.0` | Flag a row only when its time exceeds the expected time (`F` times the base, or the baseline's) by at least this many seconds |

The times come from the stamps ktest prints ([core/ktest/README.md](../core/ktest/README.md)
§ Test infrastructure): every line ktest logs opens with `[S.uuuuuu] `, the microseconds since
the kernel's timer started, the stamp the kernel console prints too. A cell runs from its
`ktest: RUN <name>` (Tier 1) or `ktest: <name> starting` (Tier 2, Tier S) line to its
`ktest: PASS <name>` or `ktest: FAIL <name>` line; a cell whose log ends before its end line is
`unfinished` and runs to the log's last stamp of any kind (a watchdog dump included), which locates
a HANG. Kernel output can share a serial line with a ktest line, since ktest writes its stamp, its
message, and the newline separately, and its UART writes take no lock the kernel console shares, so
kernel output can also land inside a message: a ktest message ends where the next stamp begins, a
`ktest: ` line whose stamp a kernel line took takes the latest stamp before it, and a cell whose end
line the output broke up is `end-lost` when ktest goes on (a later cell, tier marker, or summary
follows; ktest runs its cells one at a time), its time running to that line, an upper bound. A tier
runs from its `ktest: --- Tier <id>: ... ---` marker to the next marker or the `ktest: passed=`
summary. A name logged twice is matched by occurrence (`<name> #2`). The width is read from the
kernel's `scheduler initialised, N CPUs` line and the architecture from its
`Seraph kernel v<version> (<arch>)` banner, each else from the trailer, which also gives the host
wall time.

A comparison table lists the tier rows first, then the cells sorted by their normalised ratio,
highest first (cells missing from one side last, with a note), then three whole-run rows: the boot
(kernel timer start to `ktest: starting`), ktest's span (`ktest: starting` to the log's last
stamp), and the host wall time (from the trailer; it also covers the firmware and the
bootloader). The `FLAG` column comes first; the table ends with the count of flagged rows.

**Baseline format.** Baselines live under `xtask/baselines/ktest-timing/` as
`<arch>-<cpus>cpu.txt`, one per boundary width. A baseline is text: `#` comment lines, then
`key<TAB>value` lines, then one `tier<TAB><tier><TAB><secs>` line per tier and one
`cell<TAB><tier><TAB><name><TAB><secs><TAB><outcome>` line per cell, in log order. The keys:

| Key | Value |
|---|---|
| `format` | `1`, the format version; a file of another version is refused |
| `arch`, `cpus` | The log's architecture and width |
| `marker` | ktest's terminal marker (`ALL TESTS PASSED`), or `-` |
| `commit` | The full hash of `--commit` |
| `ktest-commit` | Present only when it is another commit: the newest commit at or before `commit` that changed anything outside Markdown, `.claude/`, `.github/`, and `xtask/baselines/` (conservatively: every change that could alter the boot image or its QEMU launch moves it, and so do some that cannot), so a baseline refreshed after a documentation-only change names the code it times |
| `date` | The UTC date the file was written |
| `host-cpu` | The host's CPU model and its count of host CPUs |
| `host-kernel` | `uname -sr` |
| `qemu` | The first line of `qemu-system-<arch> --version` |
| `accel` | The trailer's accelerator; for `kvm`, also the `kvm`, `kvm_intel`, and `kvm_amd` module parameters that move cross-CPU timing (`halt_poll_ns`, `enable_apicv`, `enable_ipiv`, `ept`, `ple_gap`, `ple_window`, `avic`, `npt`, `pause_filter_count`, `pause_filter_thresh`, those the host has) |
| `boot`, `ktest`, `wall` | The three whole-run times in seconds, or `-` |

The host values are read when the file is written, so a baseline is written on the host that ran
its log.

---

### `cargo xtask symbolize`

Resolve runtime addresses in a loaded ELF image to function, file, and line, without a debugger.
An address less the image's load bias is an address in the image's link-time address space; the
command resolves it from the image's DWARF, innermost inlined function first, each caller it is
inlined into on its own line, and, where no DWARF covers it (a build without `--debug` for that
component, or code compiled without debug information), from the image's symbol table, as the
nearest function symbol and the offset into it. Installed binaries keep their symbol tables
([docs/build-system.md](../docs/build-system.md) § Debuginfo is opt-in), so the fallback names
the function in every build. With `--log`, the addresses are those of the crash reports in a
serial log. Use cases are in [docs/testing.md](../docs/testing.md#troubleshooting)
§ Troubleshooting.

```
cargo xtask symbolize --binary PATH [--bias HEX] ADDR...
cargo xtask symbolize --kernel [--bias HEX] ADDR...
cargo xtask symbolize --log FILE
```

| Option | Default | Description |
|---|---|---|
| `--binary` | | The ELF image the addresses fall in: a sysroot binary, or its build output under `target/` |
| `--kernel` | | Resolve against the sysroot's kernel image, `sysroot/esp/EFI/seraph/kernel` |
| `--bias` | `0` | The image's load bias in hex: for a userspace process its creator's log line (procmgr `spawn image bias=0x…`, init `init: <svc> image bias=0x…`, and, for init itself, the kernel's `init: PIE bias=0x…`), for the kernel the KASLR slide from its serial-only `kaslr: slide=` line (`0` in a boot authored with `mkdisk --no-kaslr`) |
| `ADDR...` | (required without `--log`) | Runtime addresses, in hex (`0x` optional) |
| `--log` | | A serial log: symbolize every crash-report block in it (below) instead of `ADDR...` |

Each address's first line is `<address> (image <address less bias>): <resolution> [<source>]`
(the image address shown only when the bias is not `0`), where the source is the one used; a
`debug-info` resolution goes on to one line per inlined caller:

| Source | Resolution |
|---|---|
| `debug-info` | `<function> at <file>:<line>[:<column>]`, followed by one `    inlined into <function> at <file>:<line>[:<column>]` line per caller the frame is inlined into, each with the position of its call |
| `symbol-table` | `<symbol>+<offset>` |
| `unresolved` | `??`: neither source covers the address |

Names are demangled. A frame prints only what its DWARF gives: `??` for an unnamed function, and
`<function> at <file>` without a line, or a bare `<function>` without a file. An image with no
DWARF at all prints a note naming the symbol-table fallback first. An address below the bias, an
unreadable file, or a file that is not an ELF image fails the command; a compressed debug section
is refused.

**Log form.** `--log` reads the crash-report blocks crashd logs
([services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md)) with
`shared/crash-report`'s parser. A block names its process by badge; logd's
`reclaim: badge=<badge> … name=<log name>` line for that badge (or its resync form,
`reclaim (resync): badge=<badge> name=<log name>`) gives the log name, read with
`logd_codec::record::fields` (a quoted name is read whole and unescaped), and the image is the
sysroot binary named by the log name's first word, searched in `services/`, `services/drivers/`,
`services/fs/`, `programs/`, `tests/`, `tests/drivers/`, and `tests/programs/`, in that order. The
binary is used only when its executable segments span exactly the block's `text` less its
`load_bias`, the span procmgr records at spawn, so a binary rebuilt since the boot is refused
rather than resolved against. Each block prints as:

```
crash report <id> (format version <v>): process <log name>
  image: sysroot/<dir>/<log name>
  <key>=<value>
  ip=<address>  <resolution> [<source>]
  frame.<n>=<address>  <resolution> [<source>]
  …
end <id>
```

Every field line follows in the block's order, as logged. `ip`, and each `frame.<n>` inside the
block's `text`, carries its resolution in the address form's shape, the inlined-caller lines
indented below it; a frame past `frame.0` is a candidate return address, so it resolves at its
address less one, inside the call it returns from, and an `ip` outside `text` reads
`outside the image's text`.

A process that registered no log name with logd has a `reclaim:` line naming it `?` when it wrote
to the log, and none when it did not; either way its block's header reads
`process unnamed (badge <badge>: …)`. A block whose attach failed carries the fault message's badge,
which for a registered thread is its thread crash badge (procmgr's `CRASH_BADGE_TAG`, bit 63, set);
such a block names no process, and its header reads
`process unknown (thread crash badge <badge>: the attach failed, so the block names no process)`.
An unnamed process's image is then the one binary of those directories whose
executable segments span the block's text in the same way, labelled as found that way; when none or
several match, the block is not symbolized, and no name is guessed. In place of the `image:` line a
block that is not symbolized says why (the process is unnamed and its text matches no binary or
several, no sysroot binary has its name, the named binary's text differs from the block's, the
block's `arch` is not the sysroot's, it carries no `load_bias` and `text` because the report's
attach failed, a sysroot file cannot be read, or the image is not an ELF image) and, when it has a
`load_bias`, gives the address-form command that resolves its addresses once the binary is known;
its fields then print as logged. An incomplete or defective block is marked
`defective block (<defect>)` and printed all the same. A log without a block prints that it has
none. `run-parallel` writes the same report beside each log it keeps.

---

### `cargo xtask test-terminal`

Boot the terminal interactive test, exercising keyboard input end-to-end
through the live virtio-input driver and the autostarted `terminal`. Launches
QEMU headless with a QMP control socket, waits for the guest to print
`terminal: READY for injection` on the serial log, injects a known key
sequence (`help`, a stray `x`, Backspace, Return) via QMP `input-send-event`,
and asserts — host-side — that the terminal's local echo, the shell's `$ `
prompt, and the relayed `help` output (`shell built-ins:`) appear on the serial
stream. After the keyboard round passes, the transcript is cleared and the same
sequence is written to the guest UART over QEMU's bidirectional `-serial stdio`,
with the same echo, prompt, and `shell built-ins:` assertions (the serial RX
round, #291). Exits non-zero on an injection error or the 180 s timeout. This
subsumes the former standalone keyboard smoke test: the echoed `help` proves
keysym decode, and Return/Backspace prove the named-key decodes.

A pure runner — it neither builds nor stages. `terminal.svc` is in the default
boot set, so the terminal autostarts
([programs/terminal/README.md](../programs/terminal/README.md) § Scope); just build and repack:

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test-terminal [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md) for the harness model.

---

### `cargo xtask test-vmgenid`

Boot the VMGENID snapshot-resume test (#395), x86_64 only — QEMU's riscv64
`virt` machine has no VMGENID. Boots headless with a fixed generation GUID,
waits for the kernel's `entropy: vmgenid armed` and the terminal's READY
markers, saves the guest via QMP `migrate` to a state file, quits the source,
then boots a second QEMU with a different GUID and `-incoming` restoring the
state. Asserts — host-side — the kernel's `entropy: VM generation change
detected` marker and a post-resume interactive liveness round (`help` over
QMP → `shell built-ins:` on serial). Exits non-zero on a QMP error, a failed
migration, or a timeout: 180 s per marker-wait phase, 120 s for the
migrate-to-file poll, 30 s for the source to quit.

A pure runner with the same boot requirements as `test-terminal`:

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test-vmgenid [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md) for the harness model and
[core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) for the
snapshot-detection design.

---

### `cargo xtask test-kaslr`

Verify KASLR (#252) on either arch. Boots the ktest bundle headless twice with
KASLR enabled, scrapes the kernel's serial-only
`kaslr: slide=… image_base=… dm_base=…` line, and asserts the joint
`(slide, dm_base)` differs between boots (joint compare + one retry bounds a
false failure at ~1e-8). Then stages the `nokaslr` knob, repacks the disk
images in the layout they have, boots once, and asserts the deterministic layout
(slide 0, image at link base, direct map at the mode floor) — always restoring
the KASLR-enabled images in that layout.

A pure runner; requires the ktest bundle composed:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask compose-bundle --harness ktest [--arch x86_64|riscv64]
cargo xtask test-kaslr [--arch x86_64|riscv64] [--cpus N] [--mem MIB] [--riscv-mmu sv39|sv48|sv57] \
    [--x86-paging 4|5]
```

`--riscv-mmu` and `--x86-paging` have the semantics of `cargo xtask run`'s and select the mode
whose floor the `nokaslr` boot expects.

See [docs/testing.md](../docs/testing.md) for the harness model and
[docs/memory-model.md](../docs/memory-model.md) for the randomized layout.

---

### `cargo xtask test-crash-report`

Check the crash service's report blocks in a boot's saved serial log, on either arch; boots
nothing. Every block in the log must be complete and hold the fields its kind, thread, and status
require, read with `shared/crash-report`, the crate crashd emits them with
([services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md)).

```sh
# A usertest boot with crashd staged (what CI's usertest cell runs):
cargo xtask test-crash-report --log target/xtask/run-parallel-saved/x86_64-4cpu-1.log

# A boot of an image that stages no crashd (what CI's svctest cell runs):
cargo xtask test-crash-report --expect none --log target/xtask/run-parallel-saved/x86_64-4cpu-1.log
```

`--expect reports`, the default, also requires one `vm` and one `exception` block of the `crashme`
fixture's main thread and one `exception` block of a `spawned` thread (its `worker` mode), found
through the badge logd's `reclaim:` line names it by, each complete, its walk starting at its
instruction pointer, matched by the kernel's `handler declined, reason=0x<id>` line, and carrying
the stack pointer the kernel's `USERSPACE FAULT` register dump of that line's thread prints, so the
block read the thread the kernel killed. The `vm` block's `addr` must also be the faulting address
that dump prints (`cr2` on x86_64, `stval` on riscv64). `--expect none` requires the log to hold
no block. A log whose `[run-parallel]` trailer, its last line, records a `QEMU-CRASH`, a
host-emulator crash that `run-parallel` does not count as a failure, is reported skipped, which
passes the command. The model is in
[docs/testing.md](../docs/testing.md) § Crash reports.

---

### `cargo xtask test-map-redo`

Check that a boot whose bootloader redoes its steps 6 and 7 completes, on either arch. Stages the
`\EFI\seraph\mapredo` test knob, which makes the first attempt of the bootloader's steps 6 and 7
redo whatever its memory map's size ([core/boot/docs/memory-map.md](../core/boot/docs/memory-map.md)
§ Sizing the Entry Array), repacks the disk images in the layout they have, boots the current
sysroot once, and always removes the knob and repacks again in that layout afterwards. It passes
when the boot reaches its pass marker and its log holds the bootloader's line `boot: memory map:
mapredo knob present; redoing steps 6 and 7` exactly once.

A pure runner; requires a harness staged (CI runs it on the ktest bundle), and `--test-devices`
when that harness is svctest, whose devmgr phases drive the test devices (as for `run`):

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask compose-bundle --harness ktest [--arch x86_64|riscv64]
cargo xtask test-map-redo [--arch x86_64|riscv64] [--timeout SECS] [--cpus N] [--mem MIB] \
    [--riscv-mmu sv39|sv48|sv57] [--x86-paging 4|5] [--test-devices]
```

The boot runs through `run-parallel` (`--parallel 1 --runs 1`, its default pass and fail markers,
`--timeout` defaulting to 900 s) with `--save-logs` into `target/xtask/test-map-redo/`, and the
check reads the log saved there (a log an earlier boot left there is removed first). A boot that
ends `FAIL`, `HANG`, `OK` or `ERR` fails the command before the check, as it fails `run-parallel`;
a `QEMU-CRASH` boot, a host-emulator crash that `run-parallel` does not count as a failure, is
reported skipped, which passes the command.

See [docs/testing.md](../docs/testing.md) for the harness model.

---

### `cargo xtask test-debug-port`

Check the debug port's transport, on either arch. Stages the `debug-echo` fixture's recipe
([services/debug-echo/README.md](../services/debug-echo/README.md)) from `config/svcmgr/tests/` into
`config/svcmgr/services/`, repacks the disk images in the layout they have, boots the current
sysroot once with the debug port attached (as `run --debug-port` attaches it, headless), waits for
the fixture's `[debug-echo] READY on the debug port` line on the serial stream, connects to the
port, and drives one GDB remote serial protocol exchange with the fixture, framed at both ends by
`shared/gdb-rsp` ([shared/gdb-rsp/README.md](../shared/gdb-rsp/README.md)). It then kills QEMU,
removes the recipe, and repacks the images in that layout again, whatever the outcome. It passes
when every answer of the exchange arrives as expected; [docs/testing.md](../docs/testing.md) § Debug
port (`test-debug-port`) lists the exchange.

A pure runner; requires a populated sysroot:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask test-debug-port [--arch x86_64|riscv64] [--port PORT] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--port` | a free port | The host TCP port the debug port is served on; without it, a port free on `127.0.0.1` when the boot starts (below) |
| `--cpus` | `4` | vCPUs of the guest |
| `--mem` | `512` | Guest memory size in MiB |

Without `--port` the command asks the host for a port free on `127.0.0.1` (a listener bound to port
0, closed again) right before QEMU starts, so boots from several worktrees never meet on one
port; a process that binds that port in the moment between leaves QEMU unable to start, and the
boot fails. The boot to the fixture's line is bounded by five minutes and each answer by twenty
seconds. The boot is one of the two of the debug-port device cell of the local and release host runs
([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers).

---

### `cargo xtask test-gdb`

Check the GDB stub ([services/gdbstub/README.md](../services/gdbstub/README.md)) from a host GDB,
on either arch. Stages the `gdb-target` recipe (`programs/debugger --gdb-target`) from
`config/svcmgr/tests/` and the stub's template from `config/svcmgr/debug/` naming it, as
`run --debug-target gdb-target` does, repacks the disk images in the layout they have, boots the
current sysroot once with the debug port attached (headless), and waits for the stub's
`[gdbstub] attached; serving the debug port` line on the serial stream. It then runs
`gdb -nx -batch` against the port with the target's sysroot binary for symbols: the session lists
the threads, breaks on the target's tick function and continues to it, rewrites a variable and a
register and reads each back, single-steps, selects the second thread and reads its registers, and
detaches; the test then waits up to 30 s for the stub's
`[gdbstub] detached from gdb-target (crash bindings restored: ...)` line. It kills QEMU, removes
both recipes, and repacks the images in that layout again, whatever the outcome, and passes when
GDB's output shows each of those results and the stub's line reports the crash bindings restored;
[docs/testing.md](../docs/testing.md) § GDB stub (`test-gdb`) lists them.

A pure runner; requires a populated sysroot and a host GDB that debugs the architecture:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask test-gdb [--arch x86_64|riscv64] [--port PORT] [--gdb GDB] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture |
| `--port` | a free port | The host TCP port the debug port is served on; without it, a port free on `127.0.0.1` when the boot starts (below) |
| `--gdb` | `gdb` | The host GDB to run: one built with every target, or `gdb-multiarch` |
| `--cpus` | `4` | vCPUs of the guest |
| `--mem` | `512` | Guest memory size in MiB |

Without `--port` the port is picked as `test-debug-port` picks it, and GDB connects to
`127.0.0.1:<port>`. The boot to the stub's line is bounded by five minutes and the GDB session by
three. The boot is one of the two of the debug-port device cell of the local and release host runs
([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers).

---

### `cargo xtask lint-docs`

Check the mechanical documentation and source-header rules. Runs in CI's
`host-tests` job ([docs/build-system.md](../docs/build-system.md) § Continuous Integration).

```
cargo xtask lint-docs
```

Each violation prints as `<level> <rule>: <path>:<line>: <message>`; any
error-level diagnostic fails the command. The rules check what a script can
decide, including that every name the surface list of docs/testing.md
§ Coverage tiers states still names code, a file, or a directory in the tree; whether a
passage is a summary, or any other statement matches the code, is the
pre-merge review's.

| Rule | Level | Check |
|---|---|---|
| `md-columns` | error | Every line of a tracked `.md` fits the column limit in [docs/coding-standards.md](../docs/coding-standards.md) § Markdown, with the exemptions that section lists (table rows; single link, image, badge, or URL constructs; YAML front matter). |
| `src-header` | error | Every tracked `.rs`, `.ld`, `.S`, `.sh`, `.yml`: the SPDX line first (after a shebang in `.sh`; on line 2, after `/*`, in a block-comment `.ld`); exactly one blank line, then the path line; for Rust, exactly one blank line, then the `//!` block before any `#![` attribute, per [docs/coding-standards.md](../docs/coding-standards.md) § File Headers. |
| `md-summarized-by` | error | Every authoritative document ends with `---` and a `## Summarized By` section holding `None` or a non-empty list of links, each resolving to a path inside the repository (no external URL, in-page-only anchor, or `..` past the root), per [docs/documentation-standards.md](../docs/documentation-standards.md) § Backlinks and Change Propagation. |
| `md-backlink-forward` | error | Every `## Summarized By` entry names a tracked document that links this one. |
| `md-summarized-by-order` | error | The `## Summarized By` entries are sorted by the repository path each link resolves to, byte by byte, and none is listed twice. |
| `md-summarized-by-label` | error | Each `## Summarized By` entry for a `README.md` is labelled with its repository path, and each other entry with the linked document's `# Title`. |
| `md-reachable` | error | Every authoritative document is reachable by links from the root `README.md`; the root README links every `docs/*.md` and every other README links each document in its own `docs/`, per [docs/documentation-standards.md](../docs/documentation-standards.md) § Discoverability and Linking. |
| `md-coverage-symbols` | error | Every name the surface list of [docs/testing.md](../docs/testing.md) § Coverage tiers states resolves: from the paragraph starting `**Boundary surface.**` up to the one starting `**Repeat count.**`, each code span naming an item, field path, or `_*` family, and each alternative of the `S`, `M`, and `D` screen variables (groups expanded, character classes kept), matches as a whole word in the code of a tracked Rust source outside `xtask/` with `//` comments stripped, or, from the paragraph starting `**Device surfaces.**` on, in that of one inside `xtask/` other than the rule's own `lint_docs.rs`; each listed `.rs` path (`*` within one component; a bare file name in any directory) names a tracked file; and each listed directory, written with a trailing `/` (`*` within one component), has a tracked file beneath it. |
| `md-bare-cite` | warning | A `(see <name>.md)` citation outside link syntax. |

The lint treats as authoritative every tracked `.md` except the root `README.md`, `.claude/`,
`.github/`, and the per-tag release notes and template under `docs/releases/`: the documents
[docs/documentation-standards.md](../docs/documentation-standards.md) § Document Hierarchy
defines, with the release-notes exception of § Backlinks and Change Propagation. Warning-level
rules are reported and counted but do not fail the command; `md-bare-cite` is one because its
pattern also matches legitimate prose.

---

### `cargo xtask commit-check`

Check the commits of a range against [docs/conventions.md](../docs/conventions.md)
§ Commit Messages and § Commit and PR cross-references. Runs in CI's `host-tests` job on a pull
request ([docs/build-system.md](../docs/build-system.md) § Continuous Integration).

```
cargo xtask commit-check [--base <ref>] [--head <ref>] [--strict]
```

The range is `<base>..<head>`, by default `origin/master..HEAD`. Each finding prints as
`<level> <rule>: <commit>: <message>`. An error fails the command; a warning fails it only under
`--strict`. The warnings are that section's SHOULD rules, a departure from which is accepted as
that section says (a small one the PR body names, a larger one the maintainer accepts), and one
rule a script cannot decide alone.

| Rule | Level | Check |
|---|---|---|
| `commit-subject-form` | error | The subject is `<scope>: <summary>`. |
| `commit-subject-ref` | error | The subject carries no Issue reference (`#N`, `<owner>/<repo>#N`, or the Issue's URL). |
| `commit-closing-keyword` | error | No closing keyword directly before an Issue reference, in the subject or the body. |
| `commit-attribution` | error | No tool attribution line and no link to an assistant session. |
| `commit-unsigned` | error | The commit object carries a signature (a `gpgsig` header), as § Branch protection requires. Whether it verifies is that rule's to decide; a clone without the signer's key cannot. |
| `commit-subject-columns` | warning | The subject is at most 72 columns. |
| `commit-body-columns` | warning | No body line that wrapping could shorten is over 72 columns (a line with no space, or indented four columns, is left alone). |
| `commit-planning-label` | warning | The subject carries no `step N`, `phase N`, `tier N`, `stage N`, or `round N`; the name of a step a document defines permanently is not a label, which is why this is a warning. |

A merge commit is exempt from the four subject rules, as § Commit Messages says; the other rules,
`commit-body-columns` among them, apply to it.

### `cargo xtask pr-check`

Check a pull request against the rules of [docs/conventions.md](../docs/conventions.md) that a
script can decide. It reads GitHub through the `gh` CLI, which must be installed and
authenticated, and the PR's head must be in the clone (`git fetch origin`).

```
cargo xtask pr-check <N> [--gate] [--strict]
```

It runs every `commit-check` rule on the PR's commits (`origin/<base>..<head>`), then:

| Rule | Level | Check |
|---|---|---|
| `pr-unticked-box` | error | The body has no unticked task-list item (§ PR-body checklist discipline): `[ ]` after a `-`, `*`, `+`, or numbered list marker, the forms GitHub renders as a checkbox. |
| `pr-attribution` | error | The body carries no tool attribution line and no session link. |
| `pr-closes-and-refs` | warning | The body does not both close an Issue and reference it with `Refs #N`; a closing reference that names a repository (`<owner>/<repo>#N`, or the Issue's URL) is not compared. A drain PR that closes a follow-up Issue of the earlier pattern carries both (§ Follow-up Issues); in any other body the pair usually means a sentence closes an Issue the PR only references. |
| `pr-refs-unread` | warning | Every `#N` after the start of a `Refs` list on its body line is read as a referenced Issue (a line with the word but no list, such as a rule name or prose, is not checked): one the `Refs` list does not reach, because other text stands between it and the number before it, is named with its line, since its ticks and state go unchecked. A reference into another repository is not counted. |
| `pr-closing-in-prose` | warning | No closing reference stands inside a sentence: a closing keyword before an Issue reference closes that Issue when the PR merges, whatever the sentence says and even inside backticks. A line of closing references alone (`Fixes #N`), with or without a list or quote marker before it, is the intended form. |
| `pr-validation` | error | The body has a `## Validation` section that names a validated head: the first word of that section that is a commit hash in the clone. |
| `pr-validated-head` | error | The validated head is the PR head; or it is a commit of the branch (one the head holds and the base branch does not), the section says the delta since it is documentation or comments only (a phrase that pairs `only` with comments, Markdown, or documentation, such as `comment-only`, `Markdown only`, or `only in comments`, not after a `not` within three words and outside a template placeholder `<…>`; whether the phrase is about the delta stays with the auditor), and `git diff <validated> <head>` alters, Markdown (`*.md` in any letter case) aside, only comment lines and no file a build embeds ([docs/testing.md](../docs/testing.md) § Coverage tiers). A binary change, a mode change, and any non-blank line of a file type whose comment syntax the command does not know (it knows Rust, TOML, YAML, and shell) count as changes. When a merge of the base branch lies between the two heads, the command compares the PR's own change at each, `git diff <merge base> <validated>` and `git diff <merge base> <head>`, as multisets of changed lines per file, whitespace included, instead of the delta: they must differ only in comment or Markdown lines and in no file a build embeds, two binary changes agree only when their `index` lines match (the same blobs before and after, and the same mode), a change to a final newline alone is a change, as is a different mode for a file the PR adds or deletes at both heads (an added or deleted file is otherwise judged by its lines, so a file of comments alone stays comment-only), each difference is reported with the head it stands at; a line the PR reordered or moved within its own files since the validated head, which the multisets cannot see, is read from `git diff <validated> <head>` over those files less the sync's incoming diff, and a code line of it in a file whose own change compares equal is reported as moved or reordered; and the section must say the delta is documentation or comments only when the two differ at all. |
| `pr-validated-sync` | warning | No merge of the base branch lies between a validated head that passes `pr-validated-head` and the PR head. After one the body states that the incoming diff touches none of the PR's files, or that it is comment-only (§ Syncing with `master`); a reader decides the overlap and the incoming diff's kind, the command cannot. |
| `pr-milestone` | error | The pull request carries no milestone (§ Milestones). |
| `pr-closes-rolling` | error | The PR closes no rolling follow-up Issue (§ Follow-up Issues). |
| `pr-refs-rolling` | error | Every rolling follow-up Issue the body references with `Refs` is open and carries the current milestone: it is the rolling Issue of its scope in that milestone, not a rolling Issue of an earlier milestone with the same title, which step 8 of § Release Production closed after moving its open items on. |
| `issue-acceptance` | error | Every Issue the PR closes has no unticked box under its `## Acceptance` (§ Acceptance checklist discipline). |
| `issue-milestone` | error | Every Issue the PR closes carries the current milestone, the lowest-versioned open one. |
| `issue-marker-unticked` | error | On every Issue the PR closes or references with `Refs #N`, each item carrying `(fixed by PR #<N>)` is ticked. |

The command prints the Issues the body and the commits close and the ones the body references,
so that a keyword in prose that closes an Issue by accident is seen. A `Refs` keyword references
every `#N` of the list that follows it on its line (`Refs #N, #M`, `Refs #N and #M`), as
§ Commit and PR cross-references allows; the list ends at anything else, such as a remark or a
reference into another repository, and `pr-refs-unread` names a number of this repository that
it leaves after the list's start on the line. A closing reference into
another repository (`<owner>/<repo>#N`, or that Issue's URL, naming a repository other than this
one) is printed apart and not checked, since the Issue rules read this repository's Issues.

`--gate` adds the merge gate of § Branch and PR Workflow. It does not imply `--strict`: a
warning is for the reader, who may confirm it or hold an acceptance of it, and only an error
fails the gate.

| Rule | Level | Check |
|---|---|---|
| `gate-merge-state` | error | GitHub reports the merge state `CLEAN`. |
| `gate-checks` | error | Every check of the rollup has succeeded, or is neutral or skipped. |
| `gate-includes-master` | error | The base branch is an ancestor of the PR head. |
| `gate-audit-not-run` | error | The last run record for the PR head is not a run of the reviewer alone (`audit_verdict` `NOT RUN`): the audit is still owed at that head, as an `audit` record with a greater `stats.run`. |
| `gate-review-record` | error | The last run record for the PR head in `target/xtask/review/pr<N>/` is well-formed and has `AUDIT PASS`, no failed agent, and the reviewer verdict `READY TO MERGE` (or, in a record of the earlier form, `NON-BLOCKING ISSUES ONLY`). The last run at a head is the record there with the greatest `stats.run`; an earlier passing run does not count. When that record is an `audit` record that completes a run of the reviewer alone (the latest `NOT RUN` record at the head with only `audit` records after it), that run must have no failed agent and a passing verdict too. Every record at the head must be well-formed, since a malformed one cannot be placed, and two with one `stats.run` are refused. A record is at the head when its name states the head's first digits; one whose `stats.head` names another commit is refused. |
| `gate-added-files` | error | The files the PR adds can be read from the clone, which the next rule needs. |
| `gate-release-approval` | warning | The PR adds no `docs/releases/v<X>.<Y>.<Z>.md`. One that does is the release PR of § Release Production, whose merge needs the maintainer's approval (§ Pre-merge review); the command cannot read an approval, so it names the PR for its reader. |
| `gate-findings-recorded` | warning | A record of the earlier form with the verdict `NON-BLOCKING ISSUES ONLY` leaves no finding on the surface that needs a reader: one an Issue had to record (a class other than `style`, or a MUST violation), or one of any class whose `status` is `contested`. When the last record is an `audit` record that completes a run of the reviewer alone, that run's verdict and findings count too. The reader confirms each counted finding is recorded and none is contested; the command cannot. |
| `gate-defects-recorded` | warning | No defect-form record of the PR lists a defect off the surface (`recorded`). The reader confirms that each one it counts is recorded on its Issue before the merge (§ Findings); the command cannot. |

The command does not judge what needs a reader: whether the body's claims match the diff, whether
an acceptance item is delivered, and which local host runs the change owes. Those stay with the
pre-merge review's audit.

### `cargo xtask review-check`

Validate the saved run records of a pull request's pre-merge review.

```
cargo xtask review-check <N>
```

A run record is `target/xtask/review/pr<N>/<mode>-<head>.json`, where `<mode>` is `full`, `delta`,
or `audit` and `<head>` is the head the run reviewed, at least its first 8 hexadecimal digits. A
further run at a head that already has a record of that kind (a second run with the reviewer, a
second audit) is `<mode>-<head>-<n>.json`, `<n>` counting from 2. The suffix only keeps the names
apart: `stats.run` orders the runs. It is one JSON object:

| Key | Value |
|---|---|
| `verdict` | The reviewer verdict: `READY TO MERGE` or `BLOCKING ISSUES`. In an `audit` record, the reviewer verdict the audit states; in one that completes a run of the reviewer alone, that run's. |
| `audit_verdict` | `AUDIT PASS` or `AUDIT FAIL`; in a `full` or `delta` record of the reviewer alone, run while the PR body reports a run as pending, `NOT RUN`. |
| `audit` | `verdict` (as `audit_verdict`) and `sections`, a list of objects with `name`, `verdict`, and `items`; `null` in a record of the reviewer alone. |
| `findings` | The defects on the review surface. In an `audit` record, those of the last run with the reviewer that the delta leaves unfixed; in one that completes a run of the reviewer alone, that run's. |
| `recorded` | The defects off the surface. |
| `ledgered` | The findings the reviewer listed as held by the ledger. |
| `dropped` | Findings dropped as false. |
| `stats` | `form` (`defects`), `mode` (as in the file name), `head` (the full hash), `since` (the head the previous run with the reviewer reviewed, or null), `failed` (the agents that returned no result), and `run` (the run's number in the PR's sequence of runs, of either kind, counting from 1). |

Each finding is an object with `file`, `line`, `status` (`unverified` or `contested`), `issue`,
`claim`, and `fix` ([docs/conventions.md](../docs/conventions.md) § Findings).

A record without `stats.form` is of the earlier form, which records written before the defect
form use, and is checked as it was written: its reviewer verdict may also be
`NON-BLOCKING ISSUES ONLY`, and each finding also carries `class` (`correctness`, `safety`,
`contract`, `standards`, `doc-drift`, `coverage`, or `style`), `bucket` (`critical`, `should`, or
`nit`), and `must_violation` (a boolean), with the `status` `nit` allowed. Such a record still
meets the gate as it did. The command cannot tell a new record that omits `stats.form` from an
earlier one, so the `pr-review` skill writes it on every new record. A defect-form finding that
carries `class`, `bucket`, or `must_violation` is a shape error.

The command reports each departure as `error record-shape` or, for a file name that
does not state its record's mode and head, `error record-name`. A record with `audit_verdict`
`NOT RUN` and a non-null `audit`, a null `audit` with any other `audit_verdict`, or an `audit`
record with `NOT RUN` is `error record-audit-shape`; a record without an `audit` key is
`error record-shape`, since the reviewer-alone form states the `null`.

### `cargo xtask review-ledger`

Build the ledger of a review: the findings a later run must not re-raise
([docs/conventions.md](../docs/conventions.md) § Ledger).

```
cargo xtask review-ledger <N>
cargo xtask review-ledger --release <X.Y.Z> --from <previous tag> [--file <path>]...
```

With a pull request's number it reads every run record of `target/xtask/review/pr<N>/` and
writes `ledger.json` beside them: a sorted list without duplicates of each record's `recorded`
and `dropped` findings, its `contested` findings, and, in an earlier-form record whose verdict
is `NON-BLOCKING ISSUES ONLY`, all its `findings`. Each entry carries the finding's fields and
`run`, the first eight digits of the head of the run that reported it.

With `--release` it prints the release review's ledger as JSON on stdout: the entries of every
pull request a first-parent merge `Merge pull request #N` of `<previous tag>..HEAD` names, and
those of the release's own records in `target/xtask/review/release-v<X.Y.Z>/`, sorted and
without duplicates, limited to the files `--file` names when it is given. A release record's
finding the workflow left undecided (one in its `undecided` list, or a `contested` one, whose
refuters split, in its `findings`) enters only once the maintainer's decision is saved on
it as `ruling`. Only run records are read
(`<mode>-<head>[-<n>].json`); a pull request without records adds nothing. The count goes to
stderr, so stdout holds the JSON alone.

### `cargo xtask release-scope`

Print the scope of a release review as JSON, for the `release-review` workflow
(`.claude/workflows/release-review.js`), which has no file or process access of its own and
reads the scope through agents that return this command's output.

```
cargo xtask release-scope --from <previous tag> [--head <rev>] [--page-entries <n>]
cargo xtask release-scope --from <previous tag> --head <sha> [--page-entries <n>] \
    --page (files|units|issues):<n>
```

The range runs from `--from` to `--head` (`HEAD` by default). Without `--page` the command prints
the summary: `head` and `from_sha` (full SHAs), `repo_root`, `tree_at_head` (the working tree is
clean and checked out at the head), `from_ancestor`, `version_at_head` and `version_at_from`
(`[workspace.package] version` of the root `Cargo.toml`), `milestones` (the open milestones'
titles), `page_entries`, and for each of its three lists the count, the page count, and the
digest of the whole list (`range_file_count`, `range_file_pages`, `range_files_digest`;
`unit_count`, `unit_pages`, `units_digest`; `open_issue_count`, `open_issue_pages`,
`open_issues_digest`), `unit_file_entries` (the files of all units together), and `digest`.

The three lists:

- `files`: one entry per path `git diff --numstat --no-renames <from> <head>` prints, with
  `changed` (added plus deleted lines, 0 for a binary file), `at_head`, and `kind`: `rules` under
  `.claude/` or `.github/`, `markdown` for any other `.md` file, `other` for the repository
  metadata files (`LICENSE`, `.gitignore`, `.gitattributes`, `.gitkeep`, `.editorconfig`,
  `.clang-format`), and `code` for every other file.
- `units`: one per commit `git log --first-parent <from>..<head>` lists, in its order, with `sha`,
  `pr` (N when the subject is `Merge pull request #N ...`, else 0), `title` (a merge's first
  non-empty body line, else the subject), and `files`, every path
  `git diff --name-only --no-renames <sha>^1 <sha>` prints.
- `issues`: every open Issue by `number` and `title`, in ascending number. The command refuses a
  list of 1000 or more, which `gh` may have truncated.

With `--page <list>:<n>` it prints page `n` (1-based) of one list instead: `list`, `head`,
`from_sha`, `page`, `pages`, `page_entries`, `items`, and `digest`. A page holds at most
`--page-entries` entries (200 by default): a range file, an open Issue, or one file of a unit, a
unit with no file counting one. A unit's file list is split where a page fills, so each unit item
carries `file_count` (the unit's whole count) and `offset` (where its `files` start in the unit's
list); joining the items of all pages in order restores every unit.

Each `digest` is FNV-1a 64 over a sequence of fields, each field's UTF-8 bytes followed by a NUL
byte, printed as 16 hexadecimal digits; a boolean is `true` or `false` and a number is in decimal.
The fields:

| Digest | Fields, in order |
|---|---|
| a whole list | the list's name, then each entry's fields |
| a page | `list`, `head`, `from_sha`, `page`, `pages`, `page_entries`, then each item's fields |
| the summary | `summary`, `head`, `from_sha`, `repo_root`, `tree_at_head`, `from_ancestor`, `version_at_head`, `version_at_from`, `page_entries`, the count, page count and digest of `files`, `units` and `issues` in that order, `unit_file_entries`, the number of milestones, then each milestone |
| a range file | `path`, `changed`, `at_head`, `kind` |
| a unit (whole list) | `sha`, `pr`, `title`, the number of files, then each file |
| a unit item (page) | `sha`, `pr`, `title`, `file_count`, `offset`, the number of `files`, then each file |
| an open Issue | `number`, `title` |

The workflow recomputes every digest: a page or summary an agent truncated or altered fails its
own digest, and a list joined from its pages must match the summary's count and digest, so a
short, empty, or altered unit list ends the run with an error instead of a plan. The command's
test `the_digest_of_the_shared_vector_is_pinned` and the workflow's self-test pin the digest of
the same fields to the same value.

### `cargo xtask issue-edit`

Replace a GitHub Issue's body from a file, with the checks that keep a wrong file from
destroying it.

```
cargo xtask issue-edit <N> --body-file <path> [--allow-removal]
```

The command refuses an empty body. Unless `--allow-removal` is given (an edit that drops,
rewords, or reopens items on purpose, as
[docs/conventions.md](../docs/conventions.md) § Acceptance checklist discipline allows), it also
refuses a body that lacks a task-list item the Issue holds, or that reopens one the Issue has
ticked: what a copy fetched before another edit produces. An item is matched by its text, box
aside, to one of the new body whose text starts with it, so a tick that appends
`(fixed by PR #M)` keeps it. It
writes the previous body to `target/xtask/issue-backup/<N>-<time>.md`, edits the Issue, reads
it back, and restores the previous body when what GitHub holds is not what the file holds.

### `cargo xtask issue-file`

File a GitHub Issue with the labels and milestone
[docs/conventions.md](../docs/conventions.md) § Labels and § Milestones require.

```
cargo xtask issue-file --title <title> --body-file <path> --label <label>... \
    (--milestone <title> | --unscheduled)
```

The command refuses a filing without a class label, without a subsystem label, or without a
milestone decision (`--unscheduled` is for future-state work no release has scheduled). It
refuses a rolling follow-up Issue (a title ending `: defects found by review`) under anything
but the current milestone, the lowest-versioned open one, which it reads from GitHub, and one
whose title an open Issue of the current milestone already carries: the scope has its rolling
Issue there (§ Follow-up Issues). A rolling Issue of an earlier milestone carries the same title
and does not count. After
filing it reads the Issue back and fails when a label or the milestone was not applied, naming
what is missing.

### `cargo xtask orch`

Keep the state of an orchestration batch on disk, so that a session that starts with an empty
context can take the batch over (`.claude/agents/orchestrator.md` § Hand-over).

```
cargo xtask orch start --goal <text>
cargo xtask orch state [--json]
cargo xtask orch log <text>...
cargo xtask orch orchestrator [<agent-id>]
cargo xtask orch worker <name> [--id <agent-id>] [--model <m>] [--effort <e>] [--scope <s>] \
    [--branch <b>] [--worktree <path>] [--pr <N>] [--phase <phase>] [--status <text>]
cargo xtask orch worker <name> --remove
cargo xtask orch grant set <holder> <commands>...
cargo xtask orch grant clear
cargo xtask orch grant queue <holder> <commands>...
cargo xtask orch grant unqueue <holder>
cargo xtask orch order [<pr>...]
cargo xtask orch question add [--file <path>] <id> <text>...
cargo xtask orch question close <id>
cargo xtask orch ruling add <text>...
cargo xtask orch ruling drop <number>
cargo xtask orch end
```

The state is `target/xtask/orchestration/state.json`, and the batch's log is `<date>.md`
beside it, named for the UTC date of `orch start`; a second batch started on the same UTC day
appends to the same log. Both are the main checkout's: the command finds that checkout through
the git common directory, as the [host lock](#host-launch-rules) does, so run in a linked
worktree it reads and writes the same files, and a worker records its status there from its own
worktree (`.claude/agents/worker.md` § Reporting). Outside a git checkout, and in one whose git
common directory is not a `.git` directory, it uses the checkout's own `target/`. Nothing else
writes either file. A change is made under a lock file (`state.lock`), written through a
temporary file, and followed by one line in the log, `- <UTC time> <what changed>`, so the log
needs no separate upkeep; `orch log` appends a line for an event that changes no state.

| Subcommand | Effect |
|---|---|
| `start` | Creates the state and the log's first line. Refuses while a state exists. |
| `state` | Prints the state as text: goal, log, orchestrator, grant and queue, each worker, merge order, open questions, rulings. It warns on stderr when the text passes 10,000 bytes, which keeps it within the 10,000 characters a hook may add to a session's context; `worker --remove`, `question close` and `ruling drop` shorten it. `--json` prints the stored file. |
| `orchestrator` | Records the agent id workers report to. Without an id, prints the recorded one and changes nothing. |
| `worker` | Sets the named fields of a worker, creating the worker when it is new, and with `--status` the time of that report, which `state` prints beside it; fields it does not name keep their value. A phase is one of `planning`, `coding`, `review`, `gate`, `merged`, `retired`, `dead`. `--remove` drops the worker. |
| `grant set` | Records the exclusive grant and takes its holder out of the queue, and writes the grant to the host lock, where every boot not under it is refused ([Host launch rules](#host-launch-rules)). Refuses while a grant is outstanding. |
| `grant clear` | Ends the grant, in the host lock first, even one the state does not record, and then in the state. |
| `grant queue`, `grant unqueue` | Add or drop a request for the grant; a holder has at most one. |
| `order` | Replaces the merge order; no argument clears it. |
| `question add`, `question close` | Record a question the maintainer has open, with the file that holds its detail, or close it. An id is open at most once. |
| `ruling add`, `ruling drop` | Record a ruling in force, or drop one by the number `state` prints. |
| `end` | Logs the end, removes any grant from the host lock, and renames the state to `<date>.state.json` (`<date>-<n>.state.json` when that name is taken), so the next `start` begins clean. |

Every stored field is one line of at most 300 characters; longer detail belongs in a file the
field names. Text arguments take the rest of the command line, flags included, so a grant's
command list needs no quoting.

### `cargo xtask host`

Print the shared host's state as the launch rules read it ([Host launch rules](#host-launch-rules)).

```
cargo xtask host status
```

It prints the lock directory, the 1-minute load average beside each limit, the exclusive grant's
holder, each live holder (its pid, QEMU count and vCPUs, whether it runs alone or measures
timing, its checkout and command line), and the vCPU count of each QEMU running. It changes
nothing and removes no record.

### `cargo xtask hook`

Answer a hook of the assistant's harness. A hook is a command the harness runs at a fixed point
of a session: it writes the event as JSON to the command's stdin and reads the answer from its
stdout. `.claude/settings.json` names these commands; nothing else runs them.

```
cargo xtask hook bash
cargo xtask hook subagent-stop
cargo xtask hook compact-start
cargo xtask hook pre-compact
```

| Subcommand | Event | Answer |
|---|---|---|
| `bash` | `PreToolUse` of the Bash tool | Refuses, asks the maintainer, or prints nothing, per the table below. |
| `subagent-stop` | `SubagentStop` of a `worker` agent | Blocks the stop, once, when the directory the event names is a linked worktree on a detached HEAD, or one with no commit ahead of `origin/master` and no edit to a tracked file: the harness removes such a worktree, and the worker cannot be resumed (`.claude/agents/worker.md` § Reporting). The reason becomes the worker's next instruction. |
| `compact-start` | `SessionStart` after a session's compaction | Adds to the session's context what to read again from disk. `SessionStart` is an event of a session, not of a subagent: the [hooks reference](https://code.claude.com/docs/en/hooks.md) sets its `agent_type` only for a session started with `--agent`, and names only the tool events, `SubagentStart` and `SubagentStop` inside a subagent. The reminder reaches a top session, the supervisor of a batch or a session working alone; an orchestrator or a worker spawned as a subagent reads again as its agent file says, the orchestrator its state with `cargo xtask orch state`. |
| `pre-compact` | `PreCompact` | Prints the instructions for the compaction summary: keep what no file holds, leave out what the files hold. |

`bash` splits the command line into its simple commands (at `;`, `&`, `|`, a newline,
parentheses, and command substitutions), skipping the body of a here document, and reads each
behind the shell's reserved words (`if`, `then`, `do`, `!`, and the like), variable
assignments, and the wrappers `nice`, `timeout`, `env`, `ionice`, `stdbuf`, `nohup`, `time`,
`command`, and `exec`.

| Simple command | Answer |
|---|---|
| `cargo <subcommand>` other than `xtask`, `fmt`, `metadata`, `tree`, `version`, `help`, `locate-project`, and `pkgid` | Refused (`.claude/CLAUDE.md` § Tooling constraints). A toolchain selector, cargo's own options, and a path to `cargo` do not hide the subcommand. |
| `gh pr merge`, `gh issue create`, or `cargo xtask issue-file`, inside a subagent that is not the `orchestrator` | Refused: a worker neither merges nor files an Issue. A subagent is an event that carries `agent_id`. |
| `gh pr merge` that names no pull request number | Refused, since the gate cannot be checked. |
| `gh pr merge <N>` (not `gh pr merge --help`) | Runs `cargo xtask pr-check <N> --gate`. An error refuses the merge and gives the error lines. The `gate-release-approval` warning asks the maintainer, and so does a gate that could not be checked (no network, a `gh` failure). Otherwise nothing is printed. |

The split is a scan without a shell grammar: the command guards against a mistake, not against a
command line written to pass it. A hook must not stop a session, so the command always exits
with success: an event it cannot read, and a check it cannot make, is let through with a note
on stderr. The harness reads a hook's exit code 2 as a refusal, and a checkout whose `xtask`
has no `hook` command exits with that code, so `.claude/settings.json` writes each command as
`cargo xtask hook <event> || true`.

---

## Host launch rules

The worktrees of one checkout share one host. The commands that load it apply its launch rules
themselves, from `src/host_lock.rs`, before they start: `build`, `clean`, `test` and
`compare-images` as builds (`CliCommand::build_host` in `src/cli.rs` names them); `run`,
`run-parallel`, `test-terminal`, `test-vmgenid`, `test-kaslr`, `test-map-redo`, `test-debug-port`
and `test-gdb` as boots.

A boot is small when each QEMU it starts has at most 4 vCPUs and it starts at most 3 side by
side (`run-parallel` starts `min(--parallel, --runs)` per wave). Any other boot needs the host
to itself, and so does a boot started with `--alone` or `--timing`.

| Command | Admitted when | Load limit (1-minute average, below) |
|---|---|---|
| Build | No `--timing` boot runs | 32 (`BUILD_LOAD_MAX`) |
| Small boot | No boot that needs the host to itself runs, no QEMU of more than 4 vCPUs runs, and the QEMUs running plus its own are at most 3 (`SMALL_BOOTS_MAX`) | 16 (`SMALL_BOOT_LOAD_MAX`) |
| Small boot, `--alone` | No QEMU runs | 16 (`SMALL_BOOT_LOAD_MAX`) |
| More than 4 vCPUs (`SMALL_BOOT_VCPUS_MAX`), more than 3 QEMUs, or `--timing` | No QEMU runs | 10 (`LARGE_BOOT_LOAD_MAX`) |

While a boot that needs the host to itself runs, every other boot is refused, and while a
`--timing` boot runs, every build is too. The QEMUs running are counted two ways, and the
larger count holds: from the holder records below, and on Linux from `/proc`, by the whole
program name `qemu-system-*` and its `-smp` value, so a QEMU no `xtask` command started counts
too. A refusal names what is in the way: the holder, the count, or the load read and its limit.

The lock lives in `seraph-host/` in the checkout's git common directory, which every worktree
shares (in `target/xtask/host/` outside a git checkout):

- `admission.lock`: held for the length of one admission. Two commands started at the same
  moment decide one after the other, and the second sees the first's record.
- `holders/<pid>-<nanos>.json`: one record per admitted boot, held under a file lock by the
  command and by every QEMU it starts, which inherits the descriptor. A record whose lock can be
  taken belongs to no live process, and the next admission removes it, so a killed command
  leaves nothing to clean up, and its QEMUs keep the host held while they run.
- `grant.json`: the exclusive grant. `cargo xtask orch grant set` writes it, `orch grant clear`
  (whatever the batch state records) and `orch end` remove it. While it exists, a boot is refused
  unless it passes `--grant <holder>` naming its holder, and the holder's boots still meet the
  rules above. Builds are not affected.

The options:

| Option | Commands | Effect |
|---|---|---|
| `--wait-host <SECS>` | Builds and boots | On a refusal, ask again every 10 s until admitted, for at most SECS; at the bound, fail with the last refusal. Ctrl+C ends the wait at once, with the same failure. Without it a refusal fails at once. |
| `--host-override` | Builds and boots | Start even when the rules refuse, printing the refusal: for the maintainer's interactive use. A boot still registers its record, so other commands see it. |
| `--alone` | Boots | Run beside no other QEMU, and keep every other boot off the host: the re-run of a boot whose timeout or timing failure came beside another QEMU, before that failure counts (`.claude/agents/worker.md` § Host runs). |
| `--timing` | Boots | A timing-sensitive measurement: beside no other QEMU, under the 10 load limit, with builds refused while it runs. |
| `--grant <HOLDER>` | Boots | Boot under the exclusive grant of HOLDER. |

The load is the host's `getloadavg` (`/proc/loadavg` on Linux); a host that reports none is not
refused on it. On a GitHub Actions runner (`GITHUB_ACTIONS=true`) the checks are skipped with one
printed line: each CI job is its own host.

---

## Sub-crates

| Sub-crate | Purpose |
|---|---|
| [wrapper-shim/](wrapper-shim/README.md) | Tiny native binary installed into the seraph toolchain mirror as both `rustc` and `ws-clippy`. Dispatches by argv[0] basename to exec the real rustc / clippy-driver with overlay-aware `--sysroot` flags. Built by `cargo xtask build` as part of StdUser builds; never invoked directly. |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/build-system.md](../docs/build-system.md) | Toolchain, workspace layout, custom targets, sysroot, CI workflows |
| [docs/memory-model.md](../docs/memory-model.md) | Randomized kernel layout `test-kaslr` checks; RISC-V paging-mode ceiling behind `--riscv-mmu`; x86-64 paging depth behind `--x86-paging` |
| [docs/userspace-memory-model.md](../docs/userspace-memory-model.md) | PIE image placement and the per-spawn ASLR bias used with `--gdb` and `symbolize --bias` |
| [docs/storage.md](../docs/storage.md) | GPT role-GUID discovery of the data partition the disk image carries |
| [docs/testing.md](../docs/testing.md) | Harnesses, markers, and the host-driven boot tests the test commands run; the Coverage tiers surface list `lint-docs` checks; the Troubleshooting guide `symbolize` serves |
| [services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md) | The debug port `--debug-port` attaches and `test-debug-port` drives |
| [services/gdbstub/README.md](../services/gdbstub/README.md) | The GDB stub `--debug-target` stages and `test-gdb` drives |
| [docs/coding-standards.md](../docs/coding-standards.md) | Lints `build` and `test` enforce; the Markdown and file-header rules `lint-docs` checks |
| [docs/documentation-standards.md](../docs/documentation-standards.md) | Document hierarchy and backlink rules `lint-docs` checks |
| [targets/README.md](targets/README.md) | Custom target specs |

---

## Adding a new command

1. Add a variant to `CliCommand` in `src/cli.rs` with a corresponding `Args` struct, and name it
   in `CliCommand::build_host`: a command that compiles takes `HostArgs` and is admitted there as
   a build.
2. Create `src/commands/<name>.rs` with `pub fn run(ctx: &Context, args: &NameArgs) -> Result<()>`,
   or add a `pub fn run_<name>` to the module that holds its sibling commands (`pr_check`,
   `review`, and `issue` each hold two).
3. Add a match arm in `src/main.rs`.
4. Re-export the module in `src/commands/mod.rs`.

---

## Summarized By

[README.md](../README.md), [RISC-V UEFI Boot](../core/boot/docs/riscv-uefi-boot.md),
[Kernel Entropy Subsystem](../core/kernel/docs/entropy.md),
[core/ktest/README.md](../core/ktest/README.md), [Architecture Overview](../docs/architecture.md),
[Build System](../docs/build-system.md), [Coding Standards](../docs/coding-standards.md),
[Memory Model](../docs/memory-model.md), [Testing](../docs/testing.md),
[programs/terminal/README.md](../programs/terminal/README.md),
[rootfs/README.md](../rootfs/README.md),
[services/gdbstub/README.md](../services/gdbstub/README.md)
