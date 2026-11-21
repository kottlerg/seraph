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
│   ├── cli.rs                  # The command table: every command's arguments
│   ├── argparse/               # Command-line parser of the table; its reference corpus
│   │                           #   (§ Command-line parsing)
│   ├── context.rs              # Resolved workspace and build-output paths
│   ├── crash_check.rs          # The check of a log's crash-report blocks (run --crash-reports)
│   ├── crash_log.rs            # Symbolized crash reports from a serial log (symbolize --log)
│   ├── debug_stub.rs           # GDB stub staging (--debug-target)
│   ├── diag.rs                 # Diagnostics of the pull-request, record, and Issue checks
│   ├── arch.rs                 # Supported architectures and per-arch constants
│   ├── accel.rs                # Per-host QEMU acceleration-backend selection
│   ├── bundle.rs               # Bootloader bundle composition from the installed bundle lists
│   ├── disk.rs                 # GPT disk-image construction from the sysroot
│   ├── error.rs                # Error type with its context chain; Context, err!, bail!, ensure!
│   ├── fat.rs                  # FAT16/FAT32 volume writer on fatfs-parse (mkdisk)
│   ├── fat_read.rs             # FAT volume reader on fatfs-parse (the image check, the disk tests)
│   ├── firmware.rs             # Host-side discovery of QEMU pflash firmware
│   ├── fs_compat.rs            # Portable file-materialisation helpers
│   ├── gh.rs                   # GitHub CLI wrappers for the pull-request and Issue commands
│   ├── gpt.rs                  # GPT writer: protective MBR, both headers, entry arrays
│   ├── guest.rs                # A QEMU process a host-driven harness drives, and its serial reader
│   ├── host_lock.rs            # Host launch rules: the lock, the load check, admission
│   ├── image_check.rs          # The check every pack makes of the images it wrote (fsck.fat, ESP)
│   ├── qemu.rs                 # Shared QEMU argv construction
│   ├── qmp.rs                  # Minimal QMP client for the QMP-driven tests and capture-acpi
│   ├── qemu_gdb.rs             # GDB remote client: QEMU's gdbstub and the GDB stub service
│   ├── regex/                  # Pattern matching: Pike VM over the syntax of § Pattern syntax
│   ├── rust_src.rs             # In-project toolchain sysroot with the ruststd overlay
│   ├── signing/                # Signing of packed images, the signing identity, the trust
│   │                           #   store (§ Signing)
│   ├── stack_sizes.rs          # The riscv64 kernel frame check over `.stack_sizes`
│   ├── symbolize/              # ELF address resolution: DWARF, symbol-table fallback; the
│   │                           #   symbols store (store.rs: build ids, the manifest); the
│   │                           #   tests' ELF and DWARF fixture writer (fixture.rs)
│   ├── tasklist.rs             # GitHub task-list items, as the PR and Issue checks read them
│   ├── sys.rs                  # Hand-declared host C library and Windows API bindings
│   ├── sysroot.rs              # Sysroot arch checks and the rootfs/ mirror
│   ├── timing.rs               # ktest log timing parser, reports, and baseline format
│   ├── util.rs                 # Step printing, command execution, tool lookup
│   ├── commands/               # Subcommand modules (build, capture_acpi, run (the
│   │   │                       #   interactive boot; run/classified.rs, --runs),
│   │   │                       #   ktest_timing, symbolize, mkdisk, clean, crypto_vectors,
│   │   │                       #   compare_images, lint_docs, pr_check, review, release_scope,
│   │   │                       #   issue, orch, hook, host)
│   │   └── test/               # `test`: the unit tests, the cases, the cells
│   │       ├── mod.rs          # Dispatch: the unit tests, a case, a cell
│   │       ├── cases.rs        # The case registry; the runners of a case and of a cell
│   │       ├── host.rs         # The unit tests (TEST_RELAXED_LINTS)
│   │       ├── terminal.rs     # One module per case: terminal, wedge, cet, vmgenid, tpm,
│   │       │                   #   kaslr, signing, hotplug
│   │       ├── debug_port/     # The debug-port case: mod.rs; echo.rs (the transport boot),
│   │       │                   #   gdb.rs (the GDB stub boot)
│   │       └── shutdown/       # The shutdown case: mod.rs; reboot.rs, power_button.rs,
│   │                           #   core_death.rs
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

Before it compiles, the build checks that the workspace's Rust source is formatted as
`cargo fmt` formats it (`cargo fmt --all --check`) and fails on a file that is not, printing
rustfmt's diff, each hunk headed by the file and line, and the command that fixes it
(`cargo fmt --all`). It rewrites no source: running the formatter is the contributor's, as
[docs/coding-standards.md](../docs/coding-standards.md) § Formatters requires. It then runs Clippy
over the host crates, and over each component before it builds it.

The sysroot is architecture-specific. Building for a different arch than the
existing sysroot is an error — run `cargo xtask clean` first (per
[docs/build-system.md](../docs/build-system.md) § Build Output: the Sysroot).

The build installs every image under `services/`, `programs/` and `tests/` stripped
(`llvm-objcopy --strip-all`: no symbol table, no DWARF), and the kernel and the bootloader as
linked. It keeps the link output of every installed image, its symbols and DWARF with it, in the
symbols store `symbols/`, beside `sysroot/`, as `<build-id>.elf` with a manifest (a stripped
image's laid out as the strip lays it out, so the two have the same program headers, which the
build checks), and the x86-64 bootloader's PDB
as `<GUID><age>.pdb` ([docs/build-system.md](../docs/build-system.md#symbols-store) § Symbols
Store).

Every cargo command of the build runs with `CARGO_INCREMENTAL=0`, as CI's jobs build, so a local
build of a commit orders its binaries' statics as CI's does (see
[Build Profiles](../docs/build-system.md#build-profiles)); its addresses can still be offset from
CI's ([docs/testing.md](../docs/testing.md#troubleshooting) § Troubleshooting).

A riscv64 kernel build runs with `RUSTFLAGS="-Zunstable-options -Zemit-stack-sizes"`, which
reaches the `-Z build-std` crates as well, and its Clippy pass with the same flags. An x86-64
kernel build and its Clippy pass run with
`RUSTFLAGS="-Zunstable-options -Zretpoline-external-thunk"`, which sends every indirect branch of
the kernel and its `-Z build-std` crates through the kernel's retpoline thunk. After the link,
and before the image is installed, the build reads the image's `.stack_sizes` section and fails,
naming each function and its frame, when a frame passes `RISCV64_KERNEL_FRAME_MAX` (2032 bytes,
`src/stack_sizes.rs`), the kernel frame bound of
[docs/coding-standards.md](../docs/coding-standards.md) § Kernel Stack Frames. It fails as well
when the image has no such section. No other build has the check.

#### Signing

Every object a build packs is signed once, in the sysroot, as [docs/signing.md](../docs/signing.md)
§ Signing specifies: each packing of a disk image (`build`, `mkdisk` and every command that repacks)
signs in place the kernel installed at `boot/kernel` (`kernel`, the kernel role), every ELF image
under `services/`, `programs/` and `tests/` (under its install path with the role of its location,
and the boot-module role when a bundle list names it as an entry; `/services/init` as `init` with
the init role, and `/tests/ktest` too when the pack composes the ktest harness's bundle), every
regular file under a data tree (`DATA_TREES` in `src/signing/mod.rs`: `config/devmgr/platform/` and
`data/svctest/signed/`), under its install path with the data role alone, which procmgr's verified
read accepts, every regular file of a configuration directory (`CONFIG_TREES` in
`src/signing/mod.rs`: `config/svcmgr/services/`, whose files are `.svc` recipes, and
`config/devmgr/classes/`, whose files are `.class` files) under its install path in the
configuration role, the directory's `index`, which the pack writes from the files the directory
holds and signs in the configuration role under `<dir>/index` (a subdirectory or a file of another
suffix in those directories fails the pack), and every other file a bundle list names, the data
files installed under `/config/` (the boot-module role). A pack signs for the harness recorded in
`sysroot/.harness` ([docs/build-system.md](../docs/build-system.md) § Build Output: the Sysroot),
then composes the ESP (`src/esp.rs`): it copies the installed bootloader and kernel to the ESP and
composes the bundle by copying the installed files the harness's list in `config/bundle/` names
(`src/bundle.rs`). The composition signs nothing and reads no key; it verifies the kernel and each
bundle entry as the bootloader will before it writes them, and once it has written the ESP, reads it
back and refuses it unless every object on it equals its installed file and it holds no other file
than a presence-only knob ([docs/boot-media.md](../docs/boot-media.md) § The ESP; [§ The image
check](#the-image-check) makes the same check of the image the pack writes). Every signed object is
verified under the build's trust store, with each of its roles, its name and the architecture its
loaders expect, before it is written. Each command derives the store from the signing identity and
the deployer's store its environment names. `cargo xtask build` passes the store's path to the
bootloader's build in `SERAPH_BOOT_TRUST_STORE` (set by xtask, not by a user), and the bootloader
embeds it. Every pack after that (the build's own, `mkdisk` including `--repack-only`, and the
harness commands that repack) reads the store out of the installed bootloader, `boot/boot.efi`, and
refuses to sign when it is missing, holds no marker or two, or embeds another store; the error names
the image and tells to run `cargo xtask build` (docs/signing.md § Signing). Signing a pack's images
takes about half a second (`src/signing/`).

The build also Authenticode-signs the installed bootloader for UEFI Secure Boot, in place once it is
compiled, when `SERAPH_SECURE_BOOT_KEY` and `SERAPH_SECURE_BOOT_CERT` name a db key (the table
below; [docs/signing.md](../docs/signing.md) § Secure Boot): `sbsign` (sbsigntools), then
`sbverify` against the certificate, so a key that does not match its certificate fails the build.
That signature is the firmware's, apart from the objects' signatures above: the packs copy the
signed file to the ESP and read the trust store out of it as out of an unsigned one. With neither
variable set, the bootloader is not signed, and the build says so.

The signing identity is a directory outside the work tree; xtask refuses one, or a key file in
one, whose canonical path lies inside it, `target/` included. When the directory is absent or
empty and no external signer is named, the first build generates a local identity in it: a root
that certifies a signing key and is then discarded, and a store that lists the root as `LOCAL`.
The directory holds:

| File | Content |
|---|---|
| `signer.seed` | The signing key's 64-byte secret, its Ed25519 seed and its ML-DSA-65 seed ([docs/signing.md](../docs/signing.md) § Composite Signature; mode `0600`, the directory `0700`); absent when an external signer holds the key |
| `signer.cert` | The signing key's 5,409-byte certificate, or, for a key that is itself a root, `signer.pub`, its 1,984-byte composite public key |
| `trust.store` | The trust store of the anchors the identity contributes |

The build writes the trust store it signs under to `target/xtask/signing/trust-store`, before
it builds the bootloader, and rewrites the file only when the store changes. It is the store the
bootloader embeds.

| Variable | Default | Description |
|---|---|---|
| `SERAPH_SIGNING_DIR` | `seraph/signing/ed25519-ml-dsa-65-roles-1-8` in `XDG_DATA_HOME`, else in `$HOME/.local/share`, else in `LOCALAPPDATA` | The signing identity's directory; one that holds an identity of the earlier Ed25519 format is refused, and so is a signing key the build's trust store does not trust for every role, the error naming the roles it lacks. CI sets it to `$RUNNER_TEMP/seraph-signing`, so each job signs with keys it generates and discards |
| `SERAPH_SIGNER` | (none) | An external signer program, which signs in place of `signer.seed`: it reads the encoded signed attributes on its standard input and writes the 3,373-byte composite signature to its standard output. The identity directory MUST already hold the certificate (or public key) and store |
| `SERAPH_TRUST_STORE` | (none) | A deployer's trust store file, combined with the identity's |
| `SERAPH_SECURE_BOOT_KEY` | (none) | The PEM private key of the db key `build` Authenticode-signs the installed bootloader, `/boot/boot.efi`, with (`sbsign`, then `sbverify` against the certificate), so a firmware that enrols its certificate in db boots it under UEFI Secure Boot ([docs/signing.md](../docs/signing.md) § Secure Boot). Set together with `SERAPH_SECURE_BOOT_CERT`; with neither set the bootloader is not signed, and one alone is refused |
| `SERAPH_SECURE_BOOT_CERT` | (none) | The PEM X.509 certificate of `SERAPH_SECURE_BOOT_KEY`, the one a machine enrols in its db |
| `SERAPH_TRUST_STORE_MODE` | `merge` | `merge`: the union of both stores' anchors and revoked key ids, under the higher floor; two anchors of one key that differ are refused. `replace`: the deployer's store alone. Set without `SERAPH_TRUST_STORE`, it is refused |

---

### `cargo xtask run`

Boot Seraph under QEMU. `run` is a pure runner — it does not build.
Run `cargo xtask build` first; `run` errors fast if the sysroot is empty
or stamped for a different architecture.

`run` has two modes, which launch the same machine from the same launch options. Without
`--runs` it is one interactive boot: QEMU's serial output is the terminal's, and the guest has
a display window unless `--display` says otherwise. With `--runs N` it boots N times unattended,
in waves of `--parallel`, and classifies each run from its log (Classified boots below): how
CI's cells, burn-in and the local and release host runs boot, and how timing-dependent bugs
(races, lost wakeups, scheduling order) that one boot cannot reliably expose are shaken out.

```
cargo xtask run [--arch x86_64|riscv64] \
    [--cpus N] [--threads-per-core N] [--mem MIB] [--riscv-mmu sv39|sv48|sv57] \
    [--riscv-zkr on|off] [--x86-paging 4|5] [--x86-shadow-stack off|on] \
    [--iommu attached|absent] \
    [--second-disk PATH [--second-disk-block-size BYTES] [--second-disk-shared-line]] \
    [--debug-port PORT [--debug-target NAME]] [--test-devices] \
    [--display window|framebuffer|headless] [--debug-listen] [--gdb] [--verbose]

cargo xtask run --runs N [launch options] [--display framebuffer|headless] [--debug-listen] \
    [--parallel N] [--timeout SECONDS] [--pass REGEX] [--fail REGEX] [--fail-also REGEX] \
    [--require REGEX]... [--crash-reports reports|none] [--fail-grace-secs SECONDS] \
    [--hold-on-hang] [--save-logs DIR]
```

The launch options, the same in both modes:

| Option | Description |
|---|---|
| `--arch` | Target architecture (default: `x86_64`) |
| `--cpus` | Number of vCPUs to expose to the guest (default: `4`; bounded by `1..=8192`, `boot_protocol::MAX_CPUS`, the boot protocol's CPU ceiling) |
| `--threads-per-core` | Logical CPUs per core in the guest's topology (default: `1`; must divide `--cpus`). Above 1 the launch passes `-smp <cpus>,threads=<n>`, and QEMU derives the cores from it. On x86_64 the guest's `CPUID` leaf 0BH reports the SMT level under TCG and KVM alike, so `2` boots SMT sibling pairs, which the kernel's placement spreads threads across ([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md) § SMT Awareness); ktest's `integration::smt_siblings` logs the cores it finds. On riscv64 the kernel takes each hart as a core of its own whatever the topology says |
| `--mem` | Guest memory size in MiB (default: `512`) |
| `--riscv-mmu` | Guest RISC-V paging-mode ceiling (default: `sv48`; riscv64 only, ignored on x86_64). Sets the QEMU `svNN` CPU properties, which cap the `satp` modes the CPU implements (and the DTB `mmu-type` QEMU authors); the bootloader takes the DTB `mmu-type` as the candidate (Sv57 when the firmware publishes no DTB, as under EDK2) and confirms it with a `satp` write-probe that falls back to the next-narrower mode ([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § Mode negotiation), and the kernel recovers the active mode from `satp`, per [docs/memory-model.md](../docs/memory-model.md) § RISC-V (Sv39 / Sv48 / Sv57). The default pins `sv48` because QEMU ≥ 8.0 otherwise defaults the rv64 CPU to `sv57` |
| `--riscv-zkr` | Whether the guest RISC-V CPU implements the Zkr entropy source (default: `on`; riscv64 only, ignored on x86_64). Appends `zkr=on` or `zkr=off` to the QEMU `-cpu` model. With it, OpenSBI grants S-mode the `seed` CSR and the kernel's pool seeds from it beside the firmware boot seed (`entropy: seeded from hardware RNG`); `off` boots the path without the source, where the kernel's probe of the CSR traps and the pool seeds from the boot seed and jitter ([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Sources and graceful degradation). Runs with `off` are manual ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers) |
| `--x86-paging` | Guest x86-64 paging depth (default: `4`; x86_64 only, ignored on riscv64). Appends `la57=off` (`4`) or `la57=on` (`5`) to the QEMU `-cpu` model on every accelerator, which sets the CPUID LA57 bit the bootloader negotiates the depth from ([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § x86-64: Negotiated Paging Depth); the kernel recovers the depth from `CR4.LA57`, per [docs/memory-model.md](../docs/memory-model.md) § x86-64. The default pins `4` because TCG's `-cpu max` otherwise advertises LA57. `5` on a native accelerator (KVM, HVF, WHPX, NVMM) whose host CPU lacks LA57 fails before launch, naming the TCG route (`SERAPH_ACCEL=tcg`), since QEMU would drop the property with a warning and boot 4-level |
| `--x86-shadow-stack` | Whether the guest x86-64 CPU offers CET supervisor shadow stacks (default: `off`; x86_64 only, ignored on riscv64). Appends `cet-ss=off` (`off`) or `cet-ss=on,enforce` (`on`) to the QEMU `-cpu` model on every accelerator, so whether the kernel runs on shadow stacks ([core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)) is the run's choice and never the host's: `-cpu host` would otherwise pass `CET_SS` through wherever the host's KVM offers it. `on` refuses to start where the accelerator cannot offer the feature, TCG among them, rather than boot without it. A QEMU whose `-cpu help` lists no `cet-ss` flag (the CI image's 10.2) cannot offer the feature either: `off` appends nothing there, and `on` is refused before launch. The `cet` case, `cargo xtask test cet`, is where shadow stacks are booted ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers) |
| `--iommu` | Whether the machine's IOMMU is attached (default: `attached`): `intel-iommu` with interrupt remapping and 32-bit destinations offered (`intremap=on,eim=on`, under KVM on a `kernel-irqchip=split` machine) on x86-64, `riscv-iommu-pci` in Bare mode (`off=off`) at 00:01.0 on riscv64, with the `virtio-pci` devices a driver of the system binds behind it (`iommu_platform=on`). `absent` boots the no-IOMMU variant, the no-iommu device cell of the local and release host runs ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers), which keeps devmgr's unconfined path covered while the attached IOMMU confines every device a driver binds, on both architectures ([docs/device-management.md](../docs/device-management.md#dma-safety-model) § DMA Safety Model) |
| `--second-disk` | Attach `PATH` as a second disk: its own `virtio-blk-pci` device (drive `hd1`) beside `disk.img`, presenting the logical block size of its GPT (see Attached devices). `mkdisk --split-data` authors `disk-data.img` for it; any GPT image at 512- or 4096-byte blocks serves too, and any other image needs `--second-disk-block-size` |
| `--second-disk-block-size` | Logical and physical block size, in bytes, of the second disk's device, overriding the size read from its image: a power of two of at least 512, up to QEMU's own limit. A size above virtio-blk's `MAX_BLOCK_SIZE` (4096), such as `8192`, stages the refused second disk of the disk variations ([docs/testing.md](../docs/testing.md) § Coverage tiers) |
| `--second-disk-shared-line` | Place the second disk's device on the first disk's `INTx` line instead of a line of its own, and launch both disks with no MSI-X (see Attached devices), staging the boot in which two virtio-blk devices share one line. Requires `--second-disk` |
| `--debug-port` | Attach the debug port (see Attached devices): a `virtio-serial-pci` device with one `virtconsole` port, which devmgr binds as the debug port ([services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md)), its host end a TCP server on `127.0.0.1:PORT` that does not wait for a client. A host debugger connects with `target remote localhost:PORT`. The console keeps the UART on `-serial stdio` |
| `--debug-target` | Stage the GDB stub ([services/gdbstub/README.md](../services/gdbstub/README.md)) for this boot, attached to the process whose `argv[0]` is `NAME` (for a service, the first word of its recipe's `argv`): write the stub's template from `config/svcmgr/debug/` into `config/svcmgr/services/` with `NAME` appended to its `argv`, repack the disk images in the layout they have (`disk.img`'s block size, and `disk-data.img` when it is there), and print the host GDB command line, with the store file of the process binary's build id (`symbols/<build-id>.elf`) for symbols when a staged recipe or `programs/`/`services/` names it; the stub reports the load bias, so GDB relocates the symbols itself. `NAME` is one word of at most 64 bytes, procmgr's name length. The stub is removed and the images repacked in that layout when QEMU exits; a `run` interrupted before that leaves it staged until a `build` or a full `mkdisk` reinstalls the sysroot's recipes, or the next `run --debug-target`; `mkdisk --repack-only` keeps it. Requires `--debug-port` |
| `--test-devices` | Attach the test devices (see Attached devices): `edu` and five `pci-testdev` functions, which svctest's devmgr phases drive and which no other launch attaches. svctest fails, naming this flag, when they are missing. The svctest boot also needs the test class files staged ([docs/testing.md](../docs/testing.md#gating) § Gating) |
| `--display` | What the guest presents for display (see Attached devices): `window`, QEMU std VGA in a display window; `framebuffer`, the adapter with no window (`-display none`), on a host with or without a graphical backend, so the bootloader hands the kernel a GOP framebuffer and devmgr spawns the framebuffer driver: the framebuffer device cell ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers); `headless`, no adapter, so devmgr spawns no framebuffer driver. Default: `window` for the interactive boot, `headless` with `--runs`, which refuses `window` |
| `--debug-listen` | Expose the guest's gdbstub without pausing it (QEMU `-s`, tcp::1234), so a wedged guest can be attached to post hoc: `gdb -ex 'target remote :1234'`. With `--runs`, requires `--parallel 1` (one gdbstub port). Conflicts with `--gdb` |

The interactive boot's own options, which `--runs` refuses:

| Option | Description |
|---|---|
| `--gdb` | Start QEMU with a GDB server on localhost:1234; QEMU pauses at startup. Userspace binaries are PIE with a per-spawn randomized base (ASLR, #39; see [docs/userspace-memory-model.md](../docs/userspace-memory-model.md) § Image Placement): take the bias from the creator's log line (procmgr `spawn image bias=0x… (<argv0>)`, init `init: <svc> image bias=0x…`, kernel `init: PIE bias=0x…`) and load symbols with `add-symbol-file symbols/<file> -o <bias>`, `<file>` being the store file `symbols/manifest` lists for the image's install path: the installed image is stripped and carries no symbols ([docs/build-system.md](../docs/build-system.md#symbols-store) § Symbols Store) |
| `--verbose` | Show all serial output; by default output is filtered until `[--------] boot:` appears |

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
`virtio-keyboard-pci` keyboard (`id=kbd0`, the device the `terminal` case injects keys into over
QMP), a modern-only `virtio-rng-pci,disable-legacy=on` entropy source, the guest UART on `-serial
stdio`, and, unless `--iommu absent`, the machine's IOMMU: `intel-iommu,intremap=on,eim=on` on
x86-64, whose interrupt remapping makes a KVM launch's machine `q35,kernel-irqchip=split`, and
`riscv-iommu-pci` in Bare mode on riscv64, with the disks, the keyboard, and the RNG behind it
(`iommu_platform=on`).
The firmware drives the RNG first (EDK2's `VirtioRngDxe` serves the bootloader's `EFI_RNG_PROTOCOL`
draw on riscv64; OVMF binds it on x86-64, where its RDRAND driver answers the draw), and at run time
devmgr binds the `virtio-rng` driver of the `hwrng` class to it. A launch of the `tpm` case alone
(x86-64) attaches a TPM 2.0, `tpm-tis` or `tpm-crb` on an `swtpm` socket, and leaves the RNG
out ([§ The `tpm` case](#the-tpm-case)). The riscv64 IOMMU is the first
device of the command line, pinned at 00:01.0, so every auto-placed device takes a slot above it:
QEMU's ACPI RIMT describes the IOMMU as translating only the requester IDs above its own.
`--test-devices` adds, on both architectures, `-device edu,dma_mask=0xffffffff`, QEMU's DMA test
device (PCI `1234:11e8`) with a 32-bit DMA mask so its engine reaches the interrupt addresses the
forged-message phase writes, behind the IOMMU when one is attached, which only svctest's DMA
confinement and MSI phases drive
([services/drivers/test-dma/README.md](../services/drivers/test-dma/README.md)), and five QEMU
`pci-testdev` functions (PCI `1b36:0005`) at pinned addresses 0x15 (`multifunction=on`), 0x15.1
(`membar=16K`), 0x16, 0x17 (`membar=4K`) and 0x18 (`membar=8K`), which the test-only `test-fault`
driver binds ([services/drivers/test-fault/README.md](../services/drivers/test-fault/README.md)). No
other launch attaches them, and no production driver binds them. On x86-64 a launch also attaches
`-device vmgenid,guid=auto`, the VMGENID generation-ID device
([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Whole-VM-snapshot detection
(VMGENID)); QEMU's riscv64 `virt` machine has no VMGENID. `--display window` adds QEMU std VGA: the
q35 default adapter on x86-64, and on riscv64 `-device VGA` with a `qemu-xhci`/`usb-kbd` pair, added
only when a `gtk` or `sdl` display backend is available. `--display headless` drops the display
adapter, so no framebuffer is advertised. `--display framebuffer` keeps the adapter with no display
window (`-display none`): the q35 default adapter on x86-64 and `-device VGA` alone on riscv64,
whatever display backends QEMU has. `--debug-port` adds a `virtio-serial-pci` device, behind the
IOMMU when one is attached, carrying one `virtconsole` port on the character device `seraph-debug`,
a TCP server on `127.0.0.1` at the given port (`server=on,wait=off`).

The disk device presents the logical block size of the image it boots, 512 or 4096 bytes
(`logical_block_size` and `physical_block_size`), read from the LBA its GPT header sits at, so a
4Kn image from `mkdisk --block-size 4096` boots as a 4Kn disk with no launch option; every
launcher (`run` and the `test` cases) does the same. `run` attaches `--second-disk` as a
second `virtio-blk-pci` device on drive `hd1`, at its own image's block size unless
`--second-disk-block-size` sets it. A two-disk launch pins the
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
| `SERAPH_OVMF_CODE` | Direct path to the OVMF code firmware. Must be set together with `SERAPH_OVMF_VARS`, as the RISC-V pair is; the two skip the per-platform default search. |
| `SERAPH_OVMF_VARS` | Direct path to the OVMF variable-store template of the same build (`OVMF_VARS.fd`). See the pairing rule of `SERAPH_RISCV_CODE`. |
| `SERAPH_RISCV_CODE` | Direct path to `RISCV_VIRT_CODE.fd`. Must be set together with `SERAPH_RISCV_VARS` — partial overrides are rejected (a custom code image paired against the system vars template corrupts NVRAM state). |
| `SERAPH_RISCV_VARS` | Direct path to `RISCV_VIRT_VARS.fd`. See pairing rule above. |
| `SERAPH_OVMF_SECURE_CODE` | Direct path to an OVMF code image built with Secure Boot and SMM, for the Secure Boot boots (`cargo xtask test secureboot`) alone. Set together with `SERAPH_OVMF_SECURE_VARS`. |
| `SERAPH_OVMF_SECURE_VARS` | Direct path to the variable-store template of the same build. |
| `SERAPH_RISCV_SECURE_CODE` | Direct path to a `RISCV_VIRT_CODE.fd` built with Secure Boot, for the Secure Boot boots alone. Set together with `SERAPH_RISCV_SECURE_VARS`. CI sets the pair to Arch's `edk2-riscv64` images ([docs/build-system.md](../docs/build-system.md) § QEMU and Firmware). |
| `SERAPH_RISCV_SECURE_VARS` | Direct path to the variable-store template of the same build. |
| `SERAPH_ACCEL` | One of `auto` / `tcg` / `kvm` / `hvf` / `whpx` / `nvmm`. `auto` (the default) runs per-host detection. Cross-arch guests (e.g. riscv64 on x86) always resolve to `tcg`; an explicit non-`tcg`/`auto` override in that case emits a stderr warning. Unrecognized values also warn and fall through to detection. |

Default firmware search paths per host:

- **Linux** OVMF, each a code image with the variable-store template beside it, the first pair
  whose two files exist: `/usr/share/OVMF/OVMF_CODE_4M.fd` with `OVMF_VARS_4M.fd` (Debian,
  Ubuntu), `/usr/share/edk2/ovmf/OVMF_CODE.fd` with `OVMF_VARS.fd` (Fedora),
  `/usr/share/edk2/x64/OVMF_CODE.4m.fd` with `OVMF_VARS.4m.fd` (Arch),
  `/usr/share/edk2-ovmf/x64/OVMF_CODE.fd` with `OVMF_VARS.fd` (older Arch),
  `/usr/share/OVMF/OVMF_CODE.fd` with `OVMF_VARS.fd` (older Debian and Ubuntu)
- **Linux** RISC-V: `/usr/share/edk2/riscv`, `/usr/share/edk2-riscv`, `/usr/share/qemu-efi-riscv64`
- **Linux** Secure Boot, for the `secureboot` case alone: OVMF's SMM build with the template of
  its default pair, `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` (Debian, Ubuntu),
  `/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd` (Fedora) or
  `/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd` (Arch); RISC-V `/usr/share/edk2/riscv64`
  (Arch's `edk2-riscv64`, the one distribution build known to have Secure Boot). On macOS and
  BSD, QEMU's `edk2-x86_64-secure-code.fd` with `edk2-i386-vars.fd`, and no RISC-V default
- **macOS** (both): `/opt/homebrew/share/qemu`, `/usr/local/share/qemu`; OVMF is QEMU's
  `edk2-x86_64-code.fd` with `edk2-i386-vars.fd`
- **BSD** (both): `/usr/local/share/qemu`, `/usr/local/share/uefi-firmware`; OVMF is QEMU's pair
  in `/usr/local/share/qemu`
- **Windows / other**: no defaults; the relevant `SERAPH_*` env var pair is required.

Every launch, on both architectures, boots on a variable store of its own: a fresh copy of the
firmware's template, `target/xtask/vars/<pid>-<serial>.fd`, writable pflash unit 1 beside the
read-only code image, removed once its QEMU has exited. A variable the firmware or the bootloader
writes (the bootloader's security floor, [docs/signing.md](../docs/signing.md) § Rollback Floor)
is therefore seen by no later launch; the `rollback` case alone boots several times on one store.


#### Classified boots (`--runs`)

With `--runs N`, `run` boots the sysroot N times unattended and classifies each run's outcome
from its log by patterns in the syntax of § Pattern syntax. Each run boots its own copy of the
disk images (and of the riscv64 firmware variables), so the runs of a wave never share a writable
drive. The options below require `--runs`; `--debug-port` requires `--parallel 1` (one host
port), and `--debug-target` stages the GDB stub, repacking the images in the layout they have,
before the runs copy them, and removes it after the last run.

| Option | Default | Description |
|---|---|---|
| `--runs` | (interactive boot) | Total runs, dispatched in waves of `--parallel`; selects the classified boot |
| `--parallel` | `1` | Concurrency: QEMU instances in flight at once |
| `--timeout` | `30` | Per-run timeout in seconds; expired runs are SIGKILLed and classified `HANG` (unless a pass marker matched first) |
| `--pass` | `ALL TESTS PASSED` | Regex marking a successful run. The default matches the cross-harness terminal marker `[<harness>] ALL TESTS PASSED` standardised in [docs/testing.md](../docs/testing.md). On match, and every `--require` and `--crash-reports` check holding, the log is discarded and the run is classified `PASS` |
| `--fail` | `SOME TESTS FAILED\|KERNEL EXCEPTION\|FATAL:\|PANIC( at \|: )\|=== WATCHDOG\|entropy: SELFTEST FAIL` | Regex marking a failed run; the **first** match wins, the log is preserved as `FAIL-<run>.log`, and failure takes precedence over success. The default's markers are explained below the table |
| `--fail-also` | (none) | A further regex marking a failed run, matched beside `--fail` rather than in its place, so the default's markers still apply: a log matching either is `FAIL`, at `--fail`'s precedence and with its `--fail-grace-secs` kill. The framebuffer device cell passes `'framebuffer case skipped'`, so a boot in which svctest's framebuffer case skips fails |
| `--require` | (none) | A regex a line of the log must match for the run to pass; repeatable, each must match a line. A run whose `--pass` matched but whose log has no line matching one of them is `FAIL`, its reason naming the pattern |
| `--crash-reports` | (none) | Check the crash service's report blocks in each passing run's log: every block must be complete and hold the fields its kind, thread, and status require, read with `shared/crash-report`, the crate crashd emits them with ([services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md)). `reports` also requires one `vm` and one `exception` block of the `crashme` fixture's main thread and one `exception` block of a `spawned` thread (its `worker` mode), found through the badge logd's `reclaim:` line names it by, each complete, its walk starting at its instruction pointer, matched by the kernel's `handler declined, reason=0x<id>` line, and carrying the stack pointer the kernel's `USERSPACE FAULT` register dump of that line's thread prints, so the block read the thread the kernel killed; the `vm` block's `addr` must also be the faulting address that dump prints (`cr2` on x86_64, `stval` on riscv64). `none` requires no block at all. A run whose check fails is `FAIL`, its reason the check's; a `QEMU-CRASH` run is not checked. CI's svctest boot passes `none`, its usertest boot `reports`; the model is in [docs/testing.md](../docs/testing.md) § Crash reports |
| `--fail-grace-secs` | `10` | After the first `--fail` match, wait this many seconds (bounded by `--timeout`) before SIGKILL, so the trailing fault dump still lands in the log. A crashed run thus aborts ~grace seconds after the first match instead of idling to `--timeout` |
| `--hold-on-hang` | off | On a hard-timeout `HANG` (no `--fail` match), do not kill QEMU: print the attach instructions and block until the instance is terminated externally, preserving the wedged guest for a debugger. Pair with `--debug-listen`. Requires `--parallel 1` |
| `--save-logs` | off | Also copy every run's log, whatever its outcome, to `DIR/<arch>-<cpus>cpu-<run>.log`, with a trailer line `[run] arch=<a> cpus=<n> accel=<kvm\|tcg\|...> run=<r> outcome=<STATUS> wall_s=<secs>` appended. DIR is created if absent and never purged, and a file of the same name is overwritten. The copies are what `ktest-timing` reads |

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
cargo xtask run --arch x86_64 --parallel 4 --runs 100

# Custom marker
cargo xtask run --arch x86_64 --parallel 4 --runs 100 \
    --pass 'my-app: shutdown clean' --fail 'PANIC'
```

**Output**: one line per completed run, plus a summary block. Logs for
non-passing runs are preserved under `target/xtask/run/` as
`OK-<run>.log`, `FAIL-<run>.log`, `HANG-<run>.log`, `ERR-<run>.log`, or `QEMU-CRASH-<run>.log`. PASS
logs are discarded there (`--save-logs` keeps a copy of every log elsewhere). Beside each log it
keeps, in either place, whose log holds a crash-report block, a run writes the block's symbolized
report, `cargo xtask symbolize --log`'s output against the current sysroot and symbols store, as
`<name>.crash.txt` for `<name>.log`, and removes a stale `<name>.crash.txt` of a log without one; it
symbolizes only for a run that keeps its log, and a failure writing the report is a warning that
changes no outcome. Each invocation first removes the run logs and crash reports
an earlier one left under `target/xtask/run/`, so the preserved files are its own.

**Outcome precedence**:
1. `--fail` regex matches → `FAIL` (a live match also triggers early abort
   after `--fail-grace-secs`, bounded by `--timeout`; the verdict is unchanged)
2. `--pass` regex matches → `PASS` (even if QEMU was watchdog-killed,
   which is the normal case for kernels that idle after success), unless a `--require` pattern
   matches no line of the log or the `--crash-reports` check fails → `FAIL`, its reason naming the
   pattern or the defect
3. init-logd's last line, `handover complete; init-logd thread exiting`, with no userspace line
   (`[<seconds>] [<name>] ...`) after it → `FAIL`, its reason naming the lost console: real-logd,
   which owns the console from the handover on, wrote nothing to it. A run with nothing at all
   after that line, as one the watchdog cut off there, is not judged by it, nor is a run killed by
   SIGSEGV or SIGABRT (rule 6), nor a boot with no handover (ktest)
4. Watchdog timeout → `HANG`
5. Exit code 0 with no marker → `OK`
6. Killed by SIGSEGV/SIGABRT with no marker → `QEMU-CRASH` — the host emulator
   crashed, not the guest. Tallied in the summary and preserved as
   `QEMU-CRASH-<run>.log`, but does **not** fail the run (infrastructure flake,
   not a regression in the OS under test; the recurring case is the QEMU 8.2.x
   multi-threaded-TCG segfault,
   [QEMU gitlab #2220](https://gitlab.com/qemu-project/qemu/-/issues/2220)).
   SIGKILL is excluded (the `--timeout` kill, or an OOM).
7. Other exit code → `ERR rc=<n>` (a signal death is reported as `128 + signum`,
   e.g. `139` for SIGSEGV)

---

### `cargo xtask mkdisk`

Re-mirror `rootfs/` into `sysroot/`, re-synthesise test fixtures, choose what the image boots
(the harness whose bundle it composes, the bootloader's knobs, the log-level configuration), and
regenerate `disk.img` without invoking cargo. Use after editing `rootfs/` to refresh the boot
image without paying for a full `cargo xtask build` (which would also check formatting, run
clippy, and compile and install every binary). Requires a populated, arch-tagged sysroot from a
prior `cargo xtask build`.

The mirror is authoritative over the rootfs-managed subtrees (`config/`,
`data/`): files deleted from `rootfs/` are pruned from the sysroot, while
build-owned trees (`boot/`, `esp/`, `services/`, `programs/`, `tests/`) and the
synthesised `data/svctest/` fixtures are left untouched. To pack a
hand-staged sysroot that diverges from `rootfs/` — e.g. a test recipe
copied from `sysroot/config/svcmgr/tests/` into
`sysroot/config/svcmgr/services/` — use `--repack-only`, which skips the
re-mirror and packs the sysroot as it stands (a plain repack would
prune the hand-added recipe); the repository's data files (the log-level configuration and the
platform tables) are installed in either case. Every pack, `--repack-only` included, re-signs the
kernel, the ELF images and the other files a bundle list names in place ([§ Signing](#signing)), so
a hand-staged image is packed with the local identity's signature, not its own. The mirror rules are
owned by [rootfs/README.md](../rootfs/README.md).

Every pack, `mkdisk`'s included, composes the ESP from the installed files: the bootloader and
the kernel, and `sysroot/esp/EFI/seraph/bootstrap.bundle` for the harness recorded in
`sysroot/.harness`, which `cargo xtask build` records as `init` and `mkdisk --harness` as the
harness it is given; every later pack composes the same harness's bundle until another
`mkdisk --harness` or a full `cargo xtask build`. An edit to a bundle list in
`rootfs/config/bundle/` therefore reaches the bundle at the next `mkdisk`. The image carries
exactly the knobs `--knob` names: each `mkdisk` removes every other knob from `\EFI\seraph\`, so
a knob an earlier pack staged does not outlive the next `mkdisk` that omits it.

The bundle's entries are the installed files the harness's bundle list names, each by its install
path: `/config/bundle/init.x86_64.list` or `init.riscv64.list` for `init`, and
`/config/bundle/ktest.list` for `ktest`, installed from
[`rootfs/config/bundle/`](../rootfs/config/bundle/). A list holds one `init <path>` line, naming the
object of the bundle's `init` slot, and one install path per line for every other entry; `#` starts
a comment. A harness has either one list for every architecture or one per architecture, never
both. The bootloader and init address entries by name, so order is not significant. `init`'s
bundle holds 9 entries: `init`, the 6 boot modules, the IOMMU driver of the architecture's
family (`iommu-vtd` on x86-64, `iommu-riscv` on riscv64), and the log-level configuration
`/config/init/log-levels.conf`, installed from the repository's `services/init/log-levels.conf`,
or from the file `--log-levels` names. The configuration names the log level of each service init
spawns ([services/init/docs/bootstrap.md](../services/init/docs/bootstrap.md) § Log levels); an
edit to it takes effect at the next `mkdisk` or `build`, with no rebuild of a component, as does
an edit to a list. `ktest`'s bundle holds the one entry `ktest` as its `init` entry and zero
modules; ktest is monolithic and does not spawn userspace.

`disk.img` carries four GPT partitions: the EFI System Partition
(from `sysroot/esp/`), the arch-specific Seraph root (from `sysroot/`,
excluding `esp/` and `data/`), an arch-neutral `SERAPH_DATA`
partition (from `sysroot/data/`), and a 64 MiB raw swap partition of the arch-neutral
`SERAPH_SWAP` type GUID (no filesystem, left zero), always the last partition of `disk.img`. The
data partition is authored unconditionally; `mkdisk --split-data` authors it alone on a second
image, `disk-data.img` beside `disk.img`, which then carries the ESP, root and swap, for a
boot that attaches the pair (`run --second-disk disk-data.img`), and every
other authoring removes a `disk-data.img` left beside it. vfsd auto-mounts
the data partition at `/data`, on whichever disk holds it; the data tree
lives only on this partition, not on root. Every GUID the images carry is fixed (each
image's disk GUID and each partition's unique GUID), and so is every FAT volume's metadata, so
two authorings of one layout from one sysroot write identical images.
(vfsd's fall-through would also serve `/data` from a root-fs directory,
so a dedicated partition is a disk-authoring choice — the in-tree image
uses the partition, per [docs/storage.md](../docs/storage.md) § GPT Role-GUID Discovery.)
The images' logical block size, the unit of their GPT LBAs and the sector
size of their FAT volumes, is 512 bytes, or 4096 bytes (4Kn) from
`mkdisk --block-size 4096`. `build` and `mkdisk` both author the partitions above; `build`
authors them at 512 bytes on a single image, so a 4Kn or split boot runs `mkdisk` after it.
`run --debug-target` and the `terminal`, `debug-port`, `shutdown`, `hotplug`, `kaslr` and `signing`
cases repack the images in the layout they find: `disk.img`'s block size, and the data partition on
`disk-data.img` when that image is there. The cases boot that layout, attaching
`disk-data.img` as the second disk when it holds the data partition; `run` attaches a
second disk only as `--second-disk` names it.

`src/fat.rs` writes each FAT volume in one pass, with its variant chosen by its cluster count as
the FAT specification's type rule chooses it: at 4 KiB clusters the ESP (64 MiB), root
(192 MiB) and data (256 MiB) volumes are FAT16, and a volume too large for FAT16's 65524
clusters is FAT32. Each volume's data region starts on a cluster boundary, every timestamp is
1980-01-01, and the volume serial number is the first four bytes of the partition's unique GUID.
A name that is an upper-case 8.3 name is stored as that alone, and any other with a long name;
mkdisk refuses a host name FAT cannot store (one not UTF-8, one with a reserved character or a
trailing space or period, or two names of one directory that differ only in case).

#### The image check

Every pack (`build`'s, `mkdisk`'s, and each case's that repacks) checks the images it has just
written (`src/image_check.rs`), so no image exists unchecked. It reads each image's GPT through
vfsd's parser (`vfsd-gpt`), copies every partition but the raw swap partition to
`target/xtask/image-check/`, and runs `fsck.fat -n` from dosfstools, a reader independent of the
writer in `src/fat.rs` that changes nothing, on the copy. The pack fails on the first volume
`fsck.fat` does not pass, printing what `fsck.fat` printed, and when `fsck.fat` is not on
`PATH`, naming the package to install.

It then reads the ESP and the root partition of `disk.img` with xtask's FAT reader
(`src/fat_read.rs`, built on the `fatfs` service's decoders) and makes the check every pack
makes of the ESP it composes (`src/esp.rs`), of the image this time
([docs/boot-media.md](../docs/boot-media.md) § The ESP): the bootloader at both of its paths equals
`/boot/boot.efi`, the kernel `/boot/kernel`, and each entry of the bundle the installed file
its bundle list names, the list read from the root partition's `/config/bundle/` and the
harness chosen by the bundle's entries; the bundle holds every entry its list names and no other;
and the ESP holds no other file than an empty presence-only knob in `\EFI\seraph\`. The
architecture is the root partition's type. It fails naming every object that differs, is missing,
or copies a file the root partition does not install. A pack that writes substitutes in place of
installed files, as the `signing` case's refusal images do, makes the `fsck.fat` check alone, since
its ESP is by design no copy of its root partition. The check adds about half a second to a pack
at 512-byte blocks, and under a second at 4096.

```
cargo xtask mkdisk [--arch x86_64|riscv64] [--repack-only] [--harness init|ktest] \
    [--knob nokaslr|mapredo]... [--log-levels FILE] [--block-size 512|4096] [--split-data]
```

| Option | Default | Description |
|---|---|---|
| `--arch` | `x86_64` | Target architecture — must match the existing sysroot's arch tag |
| `--repack-only` | `false` | Skip the `rootfs/` re-mirror and pack the sysroot as it stands, the repository's data files installed and its objects re-signed as every pack signs them — preserves a hand-staged service set the authoritative mirror would otherwise reconcile |
| `--harness` | the recorded one | Record the harness whose bundle this and every later pack composes: `init` for the regular userspace init, `ktest` for the kernel-test harness |
| `--knob` | none | Stage a presence-only bootloader knob in `\EFI\seraph\`, repeatable or comma-separated: `nokaslr` boots the kernel at its deterministic (un-randomized) layout ([core/boot/docs/boot-flow.md](../core/boot/docs/boot-flow.md) § Step 5d: Apply the KASLR Slide), for GDB / symbolization; `mapredo` makes the first attempt of the bootloader's steps 6 and 7 redo whatever its memory map's size ([core/boot/docs/memory-map.md](../core/boot/docs/memory-map.md) § Sizing the Entry Array). Every knob not named is removed |
| `--log-levels` | the repository's | Install `FILE` at `/config/init/log-levels.conf` in place of `services/init/log-levels.conf`; refused, before anything changes, unless init's parser (`services/init/log-levels`) accepts every line, since init ignores a line it refuses |
| `--block-size` | `512` | Logical block size of the authored images: `4096` writes the GPT at 4096-byte LBAs and formats every FAT volume with 4096-byte sectors (a 4Kn disk) |
| `--split-data` | `false` | Author the data partition alone on `disk-data.img` and the ESP, root and swap on `disk.img`, both at `--block-size`; omit to author all four on `disk.img` and remove a stale `disk-data.img` |

A boot that redoes the bootloader's steps 6 and 7 logs `boot: memory map: mapredo knob present;
redoing steps 6 and 7`, which `run --runs --require` matches, once in the run
([docs/testing.md](../docs/testing.md#steps-6-and-7-redo-ktest-cell) § Steps 6 and 7 redo). A
log-levels file that sets only `vfsd = debug` (`services/init/log-levels-vfsd-debug.conf`) makes
`[vfsd] DEBUG ` and `[fatfs] DEBUG ` lines appear, fatfs logging at the level of vfsd, which spawns
it, and no `[devmgr] DEBUG ` or `[procmgr] DEBUG ` line, which `run --runs --require` and
`--fail-also` match
([docs/testing.md](../docs/testing.md#log-levels-usertest-cell) § Log levels).

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

Example — switch to ktest, run, then switch back to regular init:

```sh
cargo xtask mkdisk --arch x86_64 --harness ktest
cargo xtask run --arch x86_64 --display headless

# Reset to default-init for the next boot:
cargo xtask mkdisk --arch x86_64 --harness init
cargo xtask run --arch x86_64
```

See [docs/testing.md](../docs/testing.md) for the test-harness gating
contract.

---

### `cargo xtask clean`

Remove the sysroot, the symbols store `symbols/`, the disk images `disk.img` and
`disk-data.img`, and any per-launch variable store a killed launch left under
`target/xtask/vars/` (and optionally `target/`).

```
cargo xtask clean [--all]
```

| Option | Description |
|---|---|
| `--all` | Also run `cargo clean` to remove the `target/` directory |

---

### `cargo xtask test`

Run Seraph's tests: the unit tests, and the host-driven QEMU cases.

#### Unit tests

Check the formatting of the selected packages, lint the test code, then run Seraph unit tests on
the host target and under riscv64 emulation.

```
cargo xtask test [--component boot|protocol|kernel|init|all]
```

The formatting check runs `cargo fmt --check` over the selected packages (`--all` for `all`)
and fails on unformatted source as `cargo xtask build`'s check does, rewriting nothing, so a change
tested before its push is checked before CI reads it.

The lint pass runs `cargo clippy --tests` over the selected packages, once for
`x86_64-unknown-linux-gnu` and once for `riscv64gc-unknown-linux-gnu`, with all warnings treated as
errors, so test code gated on either architecture is linted on any host. Each pass only checks: it
builds `std` from source for its target (`-Zbuild-std=std,panic_unwind,test`), needs no rustup
target, and links nothing. `xtask` reaches the `object`, `addr2line` and `rustc_demangle` crates of
the toolchain sysroot under `rustc_private`, which link the prebuilt `core` and so cannot build
beside a `std` built from source; those two passes leave it out (`PREBUILT_STD_ONLY`), and a third
lints its test configuration for the host target alone, against the prebuilt `std`. It is
host-only, so no riscv64 Linux build of it runs. Every pass allows the lints `TEST_RELAXED_LINTS`
in `src/commands/test/host.rs` names, as [docs/coding-standards.md](../docs/coding-standards.md)
§ Clippy states.

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
their `--wait-host` and `--host-override` options. The unit-test form refuses `--arch`, `--cpus`,
`--mem`, `--release`, `--alone`, `--timing` and `--grant`.

#### Cases

The host-driven QEMU tests, which boot the current sysroot and drive or watch the boot from the
host, are cases of one registry, not commands of their own:

```
cargo xtask test <CASE> [--arch x86_64|riscv64] [--cpus N] [--mem MIB] [case options] [host options]
cargo xtask test --cell svctest|usertest|ktest [--arch A] [--cpus N] [--mem MIB] [--release] \
    [host options]
```

Without `--arch`, `--cpus` and `--mem` a case boots `x86_64` with 4 vCPUs and 512 MiB. The host
options are `--wait-host SECS`, `--host-override`, `--alone`, `--timing` and `--grant HOLDER`
([Host launch rules](#host-launch-rules)); a case or a cell is a boot under them. A case refuses a
case option it does not take, and `--cause`, `--port`, `--gdb`, `--riscv-mmu` and `--x86-paging`
require a case.

The registry is `src/commands/test/cases.rs`. Each case's entry states the architectures it runs
on with its boots on each, the bundle its image must compose, the cell that runs it, and the case
options it takes:

| Case | Arches (boots) | Bundle | Cell | Case options |
|---|---|---|---|---|
| `terminal` | x86_64 (1), riscv64 (1) | init | usertest | none |
| `wedge` | x86_64 (2), riscv64 (2) | init | usertest | none |
| `cet` | x86_64 (2) | ktest | host run | none |
| `vmgenid` | x86_64 (2) | init | usertest | none |
| `tpm` | x86_64 (2) | init | host run | none |
| `kaslr` | x86_64 (3), riscv64 (3) | ktest | ktest | `--riscv-mmu`, `--x86-paging` |
| `shutdown` | x86_64 (9), riscv64 (8) | init | usertest | `--cause` |
| `debug-port` | x86_64 (2), riscv64 (2) | init | host run | `--port`, `--gdb` |
| `signing` | x86_64 (4), riscv64 (4) | init | usertest | `--release` |
| `rollback` | x86_64 (3), riscv64 (3) | init | usertest | `--release` |
| `secureboot` | x86_64 (4), riscv64 (4) | init | usertest | none |
| `hotplug` | x86_64 (4), riscv64 (3) | init | host run | none |

Before a case runs, `test` checks that the case runs on the architecture, that the sysroot was
built for it, and that the recorded harness is the case's bundle (`ktest` for `kaslr` and `cet`,
`init` for every other), and when it is not, names the `cargo xtask mkdisk --arch A --harness X`
that records it. A case is a pure runner: it builds nothing but the `signing` case's revoking
bootloader and the `rollback` case's raising one, boots the sysroot as the last pack left it,
stages and removes only what it needs itself, and leaves the images in the layout it found them
in; the sections below state each one's staging. A new host-driven QEMU test is a case, added to
the registry and to `TestCase` in `src/cli.rs`, not a command; `cargo xtask lint-docs` fails until
the table above, a section of its own below, a heading of
[docs/testing.md](../docs/testing.md#gating) § Gating, and the cell table of its § Coverage tiers
state it (its `md-test-cells` rule, [§ `cargo xtask lint-docs`](#cargo-xtask-lint-docs)). See
[docs/testing.md](../docs/testing.md) for the harness model.

#### Cells

`cargo xtask test --cell T` runs every case the registry assigns to CI tester T's cells (the Cell
column above), on the architecture and in the registry's order, each whatever another's outcome,
and fails naming the cases that failed; for a tester with no case, `svctest` today, it says so and
succeeds. A cell takes no case option but `--release`, which it passes on to `signing` and
`rollback`. The cell table of [docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers
lists every cell with the cases it runs.

CI (`.github/workflows/build-test.yml`) runs, in every cell after the cell's own boot,
`cargo xtask mkdisk --arch A` (the plain repack: the `rootfs/` re-mirror, the repository's log
levels, no knobs, the recorded harness kept) and then `cargo xtask test --cell <tester> --arch A
[--release]`. The cases no cell runs, which are host runs
([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers), are `hotplug`, `cet`,
`tpm` and `debug-port`.

#### The `terminal` case

Boot the terminal interactive test, exercising keyboard input end-to-end
through the live virtio-input driver and the autostarted `terminal`. Stages the
GDB stub on the virtio-input driver (`/services/drivers/virtio-input`), as
`run --debug-target` stages it, launches QEMU headless with a QMP control socket
and the debug port, connects to the stub once it attaches and detaches, which
releases the driver, waits for the guest to print
`terminal: READY for injection` on the serial log, injects a known key
sequence (`help`, a stray `x`, Backspace, Return) via QMP `input-send-event`,
and asserts — host-side — that the terminal's local echo, the shell's `$ `
prompt, and the relayed `help` output (`shell built-ins:`) appear on the serial
stream. After the keyboard round passes, the transcript is cleared and the same
sequence is written to the guest UART over QEMU's bidirectional `-serial stdio`,
with the same echo, prompt, and `shell built-ins:` assertions (the serial RX
round, #291). It then kills the virtio-input driver through the stub, moving its
main thread to program counter 0, waits for the terminal's
`[terminal] input driver at ordinal 1` line once devmgr has restarted it, and
injects the key sequence again on a cleared transcript, with the echo and
`shell built-ins:` assertions (the input restart round). The stub's recipe is
removed and the disk images repacked in the layout they had afterwards. The case fails on an
injection or stub error or the 300 s timeout. This
subsumes the former standalone keyboard smoke test: the echoed `help` proves
keysym decode, and Return/Backspace prove the named-key decodes.

It stages only the GDB stub, which it removes again. `terminal.svc` is in the default
boot set, so the terminal autostarts
([programs/terminal/README.md](../programs/terminal/README.md) § Scope); just build and repack:

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test terminal [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md#interactive-input-terminal-case) § Interactive input.

#### The `wedge` case

Check the softlockup watchdog's report of a CPU wedged in the kernel with interrupts off, on either
arch ([docs/testing.md](../docs/testing.md#interrupts-off-wedge-wedge-case) § Interrupts-off wedge).
Boots the current sysroot's default boot headless twice, with QEMU's gdbstub on a unix socket under
`target/xtask/`, and waits for the terminal's `terminal: READY for injection` line, reading the
KASLR slide and each CPU's hardware id from the kernel's boot lines. It then stops the VM over the
GDB remote serial protocol, moves the chosen CPU's program counter from the idle loop's halt to the
kernel's `halt_loop`, which masks interrupts and halts for good, resumes the VM, and checks the
watchdog's report. The first boot wedges the highest-numbered AP, the second the BSP. On x86_64
the report must also hold the wedged CPU's NMI frame with its `rip` inside `halt_loop`.

It reads the kernel's symbols from the sysroot's kernel image:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask mkdisk [--arch x86_64|riscv64]
cargo xtask test wedge [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

The guest has at least 2 vCPUs. The boot to the READY line is bounded by five minutes, each gdbstub
reply by twenty seconds, the search for the CPU halted in the idle loop by 100 stops 100 ms apart,
and the report by two minutes. The case fails, killing QEMU, on any of those bounds, on a gdbstub
it cannot reach, and on a report line that is missing or wrong.

#### The `cet` case

Check the kernel's CET supervisor shadow stacks, x86_64 only
([docs/testing.md](../docs/testing.md#cet-shadow-stacks-cet-case) § CET shadow stacks). Boots the
current sysroot headless twice under KVM with `-cpu host,cet-ss=on,enforce`: the first runs ktest
to its pass marker and requires the kernel's `shadow stacks: on` line before it (a kernel that
logs `shadow stacks: off` instead, which it does on a CPU reporting `CET_SS` without enhanced or
Automatic IBRS, since it then takes the retpoline sequence, fails the case naming that cause);
the second, with
QEMU's gdbstub on a unix socket under `target/xtask/`, sets a hardware breakpoint at
`syscall::dispatch` once ktest has started, overwrites the return address at the stopped CPU's
stack pointer, resumes, and requires the kernel's report of `#CP` (vector 21, error code 1) at an
address inside `dispatch`, trying up to five calls.

A boot whose kernel faults with the exception report's `cet:` line showing `s_cet` without
`SH_STK_EN` and `int_ssp_table=0` ran on a host that lost the guest's CET state. On a host with the
CPUID hypervisor bit the case reports the run as inconclusive and boots again, up to four runs
of each boot, passing only on a run without it and failing as inconclusive after four; on any other
host that report fails the case
([docs/testing.md](../docs/testing.md#cet-shadow-stacks-cet-case) § CET shadow stacks).

The sysroot must hold the composed ktest bundle, and the case reads the kernel's symbols
from the sysroot's kernel image:

```sh
cargo xtask build --arch x86_64
cargo xtask mkdisk --harness ktest
cargo xtask test cet [--cpus N] [--mem MIB]
```

Each boot is bounded by five minutes and each gdbstub reply by 30 s. The case fails, killing
QEMU, on any of those bounds, on a gdbstub it cannot reach, and on a missing or wrong line. It
fails before the boots without KVM, and QEMU refuses to start, which fails it naming the refused
feature, when the host's CPU or KVM cannot give the guest CET shadow stacks: it never passes
without running them.

#### The `vmgenid` case

Boot the VMGENID snapshot-resume test (#395), x86_64 only — QEMU's riscv64
`virt` machine has no VMGENID. Boots headless with a fixed generation GUID,
waits for the kernel's `entropy: vmgenid armed` and the terminal's READY
markers, saves the guest via QMP `migrate` to a state file, quits the source,
then boots a second QEMU with a different GUID and `-incoming` restoring the
state. Asserts — host-side — the kernel's `entropy: VM generation change
detected` marker and a post-resume interactive liveness round (`help` over
QMP → `shell built-ins:` on serial). The case fails on a QMP error, a failed
migration, or a timeout: 180 s per marker-wait phase, 120 s for the
migrate-to-file poll, 30 s for the source to quit.

```sh
cargo xtask build
cargo xtask mkdisk
cargo xtask test vmgenid [--cpus N] [--mem MIB]
```

See [docs/testing.md](../docs/testing.md#snapshot-resume-vmgenid-case) § Snapshot resume for the
harness model and [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) for the
snapshot-detection design.

#### The `tpm` case

Check the TPM 2.0 driver, x86_64 only: QEMU's TPM devices sit in the PC Client TPM range, which
the riscv64 `virt` machine does not decode
([docs/testing.md](../docs/testing.md#tpm-tpm-case) § TPM). Boots the current sysroot headless
twice, once with QEMU's `tpm-tis` device (the FIFO interface) and once with `tpm-crb` (the CRB
interface), each backed by an `swtpm` emulator the case starts on a fresh state directory
under `target/xtask/tpm/`, so each boot meets a TPM no firmware or earlier boot has used. A TPM
launch leaves `virtio-rng-pci` out, so the TPM driver is the `hwrng` class's only member, and
OVMF's own RDRAND-backed `EFI_RNG_PROTOCOL` answers the bootloader's draw. Each boot passes on the
TPM driver's line naming the interface it found, its `first READ answered:` line, and
entropyd's `entropy contribution accepted:` line naming `hwrng ordinal 0`, which can then only
be the TPM's.

The host needs `swtpm` (the `swtpm` package; the case names the install command of each common
distribution when it is missing):

```sh
cargo xtask build --arch x86_64
cargo xtask mkdisk
cargo xtask test tpm [--cpus N] [--mem MIB]
```

Each boot is bounded by three minutes, and `swtpm` by ten seconds to create its control socket.
The case fails, killing QEMU and the emulator, on either bound, on an emulator that exits
early, and on a missing line. See
[services/drivers/docs/tpm.md](../services/drivers/docs/tpm.md) for the driver's design.

#### The `kaslr` case

Verify KASLR (#252) on either arch. Boots the ktest bundle headless twice with
KASLR enabled, scrapes the kernel's serial-only
`kaslr: slide=… image_base=… dm_base=…` line, and asserts the joint
`(slide, dm_base)` differs between boots (joint compare + one retry bounds a
false failure at ~1e-8). Then stages the `nokaslr` knob, repacks the disk
images in the layout they have, boots once, and asserts the deterministic layout
(slide 0, image at link base, direct map at the mode floor) — always restoring
the KASLR-enabled images in that layout.

The sysroot must hold the composed ktest bundle:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask mkdisk --harness ktest [--arch x86_64|riscv64]
cargo xtask test kaslr [--arch x86_64|riscv64] [--cpus N] [--mem MIB] \
    [--riscv-mmu sv39|sv48|sv57] [--x86-paging 4|5]
```

`--riscv-mmu` and `--x86-paging` have the semantics of `cargo xtask run`'s and select the mode
whose floor the `nokaslr` boot expects.

See [docs/testing.md](../docs/testing.md#kaslr-randomization-kaslr-case) § KASLR randomization for
the harness model and [docs/memory-model.md](../docs/memory-model.md) for the randomized layout.

#### The `shutdown` case

Check that the machine shuts down for each cause, on either arch, one boot per cause. The boots
run one at a time, admitted once as the case starts, and each runs whatever another's outcome; the
case fails naming the causes that failed. It requires a populated sysroot with the default boot set
(terminal + shell):

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask test shutdown [--arch x86_64|riscv64] [--cause NAME[,NAME...]] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--cause` | every cause of the arch | The causes to boot for, one boot each, in the order below however they are named: `reboot`, `power-button` (x86_64 only), `memmgr`, `procmgr` (a request worker), `procmgr-reaper` (procmgr's reaper thread), `svcmgr`, `devmgr`, `vfsd`, `logd`; repeatable, or comma-separated |

Without `--cause` the case makes nine boots on x86_64 and eight on riscv64. A cause the arch does
not have is refused. Each boot is headless with a QMP socket, and passes on QMP's `SHUTDOWN` event
giving the cause's reason, with QEMU exiting on its own; each boot to its marker is bounded by
five minutes.

**Reboot.** Stages the `reboot` fixture's recipe
(`rootfs/config/svcmgr/tests/reboot.svc`: svctest's `reboot` role, seeded with
`pwrmgr.shutdown`) from `config/svcmgr/tests/` into `config/svcmgr/services/`, repacks the disk
images in the layout they have, and boots the current sysroot. The fixture sends pwrmgr `REBOOT`.
QEMU runs with `-no-reboot`, so the reset ends it, and QMP's
`SHUTDOWN` event names the cause. It then removes the recipe and repacks the images in that
layout again, whatever the outcome. It passes when the fixture's `reboot fixture: requesting
REBOOT` line appears, on `x86_64` acpid's `RESET: RESET_REG` line too, the `SHUTDOWN` event's
reason is `guest-reset` (a power-off gives `guest-shutdown`), and QEMU exits on its own with
success within 30 seconds of the event; [docs/testing.md](../docs/testing.md#reboot-shutdown-case)
§ Reboot says what each architecture's path is. The QMP socket is
`target/xtask/reboot-test-<arch>.sock`.

**Power button** (x86_64 only: QEMU's riscv64 `virt` machine has no fixed power button). Boots the
current sysroot, and waits up to five
minutes for acpid's `events armed` line and the terminal's READY line. It then presses the ACPI
power button with QMP `system_powerdown` and waits on the same connection for QMP's `SHUTDOWN`
event. It passes when acpid's `power button pressed` line, pwrmgr's `power button: shutting down`
line and acpid's `SLEEP(5): PM1a_CNT` line appear within a minute of the press, the `SHUTDOWN`
event's reason is `guest-shutdown`, and QEMU exits on its own within 30 seconds;
[docs/testing.md](../docs/testing.md#power-button-shutdown-case) § Power button says what the
press runs through. The QMP socket is `target/xtask/powerbutton-test.sock`.

**Core death** (`memmgr`, `procmgr`, `procmgr-reaper`, `svcmgr`, `devmgr`, `vfsd`, `logd`: the
death of a core or critical service powers the system off). Each boot kills its cause's service by
moving one of its threads to program counter 0. svcmgr, devmgr, vfsd and logd are reached through
the GDB stub service, which the case stages naming the target and boots with the debug port, as
`run --debug-target` does, removing it again and repacking the disk images in the layout they had,
whatever the outcome; logd is killed four times, once more than svcmgr's restart budget allows,
and when init-logd's last line, `handover complete; init-logd thread exiting`, has not appeared
before the first kill (the first instance died before its bootstrap request or after it, before its
release), the restart must produce it.
memmgr and procmgr are reached through QEMU's own gdbstub, on a unix socket, with a hardware
breakpoint on a function of the target's binary, read from the symbols store's file of its build id,
hit by a `hello` the case types at the shell once the terminal's READY line and pwrmgr's
`core-death power-off armed` line have appeared. It passes for a cause when QMP's `SHUTDOWN` event,
after the kill, gives reason `guest-shutdown`, and QEMU exits on its own within two minutes of the
kill; [docs/testing.md](../docs/testing.md#core-death-shutdown-case) § Core death says when each
target is killed and which path powers the system off. A main thread whose program-counter write
the stub refuses as held in a call (`E06`) has its program counter read and written again every
100 ms until the call returns, for up to 60 s. The QMP and gdbstub sockets are
`target/xtask/core-death-<pid>.qmp` and `.gdb`.

#### The `debug-port` case

Check the debug port on either arch in two boots, the second whatever the first's outcome: the
transport against the `debug-echo` fixture, then the GDB stub from a host GDB.

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask test debug-port [--arch x86_64|riscv64] [--port PORT] [--gdb GDB] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--port` | a free port | The host TCP port the debug port is served on; without it, a port free on `127.0.0.1` when each boot starts (below) |
| `--gdb` | `gdb` | The host GDB the stub boot runs: one built with every target, or `gdb-multiarch` |

**The transport boot.** Stages the `debug-echo` fixture's recipe
([services/debug-echo/README.md](../services/debug-echo/README.md)) from `config/svcmgr/tests/` into
`config/svcmgr/services/`, repacks the disk images in the layout they have, boots the current
sysroot once with the debug port attached (as `run --debug-port` attaches it, headless), waits for
the fixture's `[debug-echo] READY on the debug port` line on the serial stream, connects to the
port, and drives one GDB remote serial protocol exchange with the fixture, framed at both ends by
`shared/gdb-rsp` ([shared/gdb-rsp/README.md](../shared/gdb-rsp/README.md)), then a restart round
on the same connection: through QEMU's gdbstub, which the boot attaches on a socket under
`target/xtask/`, the host kills the port's `virtio-console` driver at a hardware breakpoint in its
code, its bias taken from procmgr's `spawn image bias=0x… (/services/drivers/virtio-console)`
line, waits for the fixture's `[debug-echo] debug port driver at ordinal 1` line, and echoes
through the restarted driver. It then kills QEMU, removes the recipe, and repacks the images in
that layout again, whatever the outcome. It passes when every answer of the exchange and of the
restart round arrives as expected;
[docs/testing.md](../docs/testing.md#debug-port-debug-port-case) § Debug port lists the exchange.

**The GDB stub boot.** Checks the GDB stub
([services/gdbstub/README.md](../services/gdbstub/README.md)) from a host GDB. Stages the
`gdb-target` recipe (`programs/debugger --gdb-target`) from `config/svcmgr/tests/` and the stub's
template from `config/svcmgr/debug/` naming it, as `run --debug-target gdb-target` does, repacks the
disk images in the layout they have, boots the current sysroot once with the debug port attached
(headless), and waits for the stub's `[gdbstub] attached; serving the debug port` line on the serial
stream. It then runs `gdb -nx -batch` against the port with the symbols store's file of the target
binary's build id for symbols: the session lists the threads, single-steps from where the attach
stopped the main thread, breaks on the target's tick function and continues to it, rewrites a
variable and a register and reads each back, single-steps again, selects the second thread and reads
its registers, and detaches; the case then waits up to 30 s for the stub's `[gdbstub] detached from
gdb-target (crash bindings restored: ...)` line. A restart round follows: the case connects to the
stub, which attaches to the target anew, kills the port's driver through QEMU's gdbstub as the
transport boot does, waits for the stub's `[gdbstub] debug port driver at ordinal 1` line, and
requires the session to go on on the same connection (`?`, `Hg1`, the pointer read, `D`). It kills
QEMU, removes both recipes, and repacks the images in that layout again, whatever the outcome, and
passes when GDB's output shows each of those results, the stub's line reports the crash bindings
restored, and the restart round passes;
[docs/testing.md](../docs/testing.md#gdb-stub-debug-port-case) § GDB stub lists them. The host needs
a GDB that debugs the architecture.

Without `--port` the case asks the host for a port free on `127.0.0.1` (a listener bound to port
0, closed again) right before each QEMU starts, so boots from several worktrees never meet on one
port; a process that binds that port in the moment between leaves QEMU unable to start, and the
boot fails. GDB connects to `127.0.0.1:<port>`. The boot to the fixture's line or the stub's is
bounded by five minutes, each answer of the exchange by twenty seconds and the GDB session by
three minutes. The two boots are the debug-port device cell of the local and release host runs
([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers).

#### The `signing` case

Check that every signature verifier refuses an object that does not verify, with the refusal it
owes, on either arch ([docs/signing.md](../docs/signing.md) § Which Stage Verifies What). The
case packs the disk images once with the default-init bundle, so the sysroot is signed and the
ESP holds that bundle, composed from the installed files; writes each boot's objects into
`target/xtask/test/signing/<arch>/` from the signed ones; and boots the current sysroot six
times, each from images packed with the default-init bundle and those objects in place of the
ESP's or the sysroot's files (`disk::create_disk_image_substituting`):

| Boot | Objects in place of the sysroot's | Owed lines |
|---|---|---|
| `kernel` | the kernel with a body byte flipped | `SERAPH BOOT FATAL: signature verification refused: kernel: Failed(BodyHash)` |
| `bundle` | the bundle with a body byte of its `/services/drivers/virtio-blk` entry flipped | `SERAPH BOOT FATAL: signature verification refused: /services/drivers/virtio-blk: Failed(BodyHash)` |
| `revoked` | both ESP copies of the bootloader, built under the build's trust store with the signing key's id revoked | `SERAPH BOOT FATAL: signature verification refused: kernel: Failed(Revoked)` |
| `rootfs` | `/services/timed` with a body byte flipped, `/services/pwrmgr` signed with the data role alone, `/services/crashd` signed by a key no anchor holds; the kernel and `/programs/terminal` each with a record of that key before their own; on riscv64 also `/config/devmgr/platform/qemu-virt.platform` with a body byte flipped | procmgr's `signature verification refused: <path>: <refusal>` (`Failed(BodyHash)`, `Failed(Role)`, `Untrusted`) and svcmgr's `create: "<path>" refused: its signature did not verify` for each of the three, and `terminal: READY for injection`; on riscv64 also procmgr's `signature verification refused: /config/devmgr/platform/qemu-virt.platform: Failed(BodyHash)` and devmgr's `platform table /config/devmgr/platform/qemu-virt.platform: procmgr's verified read refused it (InvalidData); passed over` and `no platform description table for this machine; no platform-table records` |
| `configuration` | a bootloader built under the build's trust store with two more anchors, one trusted for every role but configuration and one for configuration alone; in `/config/svcmgr/services/`, `timed.svc` with a body byte flipped, `pwrmgr.svc` unsigned, `crashd.svc` signed by the first anchor's key, `oomd.svc` signed by the second's, which signs `/services/oomd` as a service too, `entropyd.svc` validly signed over a body other than the one the index holds, and an index, validly signed, that names a `removed.svc` the directory lacks and omits the `swapd.svc` it holds; `/config/devmgr/classes/rtc.class` with a body byte flipped | procmgr's `signature verification refused: <path>: <refusal>` for `timed.svc` (`Failed(BodyHash)`), `pwrmgr.svc` (`Parse(Magic)`), `crashd.svc` (`Failed(KeyUsage)`) and `rtc.class` (`Failed(BodyHash)`), each followed by svcmgr's `<path>: named by the index, not read (InvalidData); dropped` (for `rtc.class`, `...; class not configured`); procmgr's refusal of `/services/oomd` (`Failed(KeyUsage)`) and svcmgr's `create: "/services/oomd" refused: its signature did not verify`; svcmgr's `/config/svcmgr/services/entropyd.svc: its body is not the one the directory's index was signed with; refused`, followed by its `named by the index, not read (InvalidData); dropped`; `/config/svcmgr/services/removed.svc: named by the index, not read (NotFound); dropped`; `/config/svcmgr/services/swapd.svc: not named by the directory's index; not read`; and `terminal: READY for injection` |
| `index` | the indexes of `/config/svcmgr/services/` and `/config/devmgr/classes/` each with a body byte flipped | procmgr's `signature verification refused: <index path>: Failed(BodyHash)` for each, svcmgr's `<index path> not read (InvalidData); no recipe is read` and `<index path> not read (InvalidData); no device class configured`, and `svcmgr: registered without definition: ` |

The untrusted key is a local identity generated for the run in a directory under the host's
temporary directory, outside the work tree, and removed again. A boot passes once every owed line
has appeared, in any order; it fails at once on another refusal line or a fatal marker (`KERNEL
EXCEPTION`, `FATAL:`, a panic, the watchdog, the entropy self-test), and fails at its deadline,
three minutes for a boot the bootloader ends and six for `rootfs`, naming the lines still missing. A
staged test harness's own verdict is not judged. The host kills QEMU. Every boot's serial log is
saved as `target/xtask/test/signing/<arch>/<boot>.log`, and the case reports every boot before it
fails. The images are packed again from the sysroot in the layout they had, with the recorded
harness's bundle, whatever the outcome; no boot changes a sysroot file, so a later pack cannot sign
a tampered body.

The case compiles the bootloader of the `revoked` boot, so the host admits it as a build and
then each boot as one boot of `--cpus` vCPUs (§ Host launch rules). The compile reuses the
bootloader's cargo output directory, so the next `cargo xtask build` compiles the bootloader
again.

It requires a populated sysroot of the profile `--release` names:

```sh
cargo xtask build [--arch x86_64|riscv64] [--release]
cargo xtask test signing [--arch x86_64|riscv64] [--release] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--release` | `false` | Build the `revoked` boot's bootloader in release mode, as the sysroot's was built; a cell passes it on |

#### The `rollback` case

Check that the bootloader keeps the machine's security floor in firmware storage, raises it, and
refuses itself below it, on either arch ([docs/signing.md](../docs/signing.md) § Rollback Floor).
The case packs the disk images once with the default-init bundle, so the sysroot is signed; reads
the floor `F` of the build's trust store; writes the `raised` boot's objects into
`target/xtask/test/rollback/<arch>/`; and boots the current sysroot three times on one variable
store, one fresh copy of the firmware's template kept across the three boots and removed after the
last, so each boot reads the floor the one before it left:

| Boot | Objects in place of the sysroot's | Owed lines |
|---|---|---|
| `first` | none | `boot: security floor: machine none, trust store F` and `boot: security floor: machine raised to F` |
| `raised` | both ESP copies of the bootloader, built under the build's trust store with the floor `F + 1`; the kernel and every bundle entry signed again at security version `F + 1` | `boot: security floor: machine F, trust store F + 1` and `boot: security floor: machine raised to F + 1` |
| `older` | none | `SERAPH BOOT FATAL: this bootloader is older than the machine's security floor: machine floor F + 1, trust store floor F` |

A boot is judged as the `signing` case judges one, with a deadline of three minutes; a boot after
a failed one is not made, since it would read a floor its predecessor did not leave. Every boot's
serial log is saved as `target/xtask/test/rollback/<arch>/<boot>.log`. The images are packed
again from the sysroot in the layout they had, with the recorded harness's bundle, whatever the
outcome. A firmware that refuses the floor's write is not reached by any QEMU firmware on demand;
the bootloader's host tests cover it (`core/boot/src/rollback.rs`).

The case compiles the `raised` boot's bootloader, as the `signing` case compiles its own, and is
admitted the same way. It requires a populated sysroot of the profile `--release` names:

```sh
cargo xtask build [--arch x86_64|riscv64] [--release]
cargo xtask test rollback [--arch x86_64|riscv64] [--release] [--cpus N] [--mem MIB]
```

| Option | Default | Description |
|---|---|---|
| `--release` | `false` | Build the `raised` boot's bootloader in release mode, as the sysroot's was built; a cell passes it on |

#### The `secureboot` case

Check UEFI Secure Boot of the bootloader on either arch ([docs/signing.md](../docs/signing.md)
§ Secure Boot): the firmware boots the bootloader signed with an enrolled key and refuses it
tampered or unsigned, and the bootloader logs the state. The case generates a development platform
key, key exchange key and db key (`openssl`, RSA-2048 with SHA-256) into
`target/xtask/test/secureboot/<arch>/keys/`; strips any signature from the installed bootloader
and signs it with the db key (`sbsign`, checked with `sbverify`); flips a byte of the signed
image's code section, a byte the signature covers, and checks that `sbverify` then refuses it;
and boots the current sysroot four times, each on a variable store of its own, the image in place
of both ESP copies of the installed bootloader:

| Boot | Firmware and store | Bootloader | Owed line |
|---|---|---|---|
| `enrolled` | the Secure Boot firmware, the three keys enrolled (`virt-fw-vars`) | signed | the bootloader's `boot: Secure Boot: on` |
| `tampered` | as `enrolled` | signed, a code byte flipped | the firmware's `Access Denied -- rejected probably by Secure Boot` |
| `unsigned` | as `enrolled` | no signature | the firmware's refusal, as `tampered` |
| `default` | the default firmware, its template's store | the installed one | the bootloader's `boot: Secure Boot: off` |

The Secure Boot firmware is a pair of its own (`SERAPH_OVMF_SECURE_CODE` with
`SERAPH_OVMF_SECURE_VARS`, `SERAPH_RISCV_SECURE_CODE` with `SERAPH_RISCV_SECURE_VARS`, else the
default paths of [§ Environment variables](#environment-variables)): the default pair has no
Secure Boot on x86_64, and on riscv64 has it only on some distributions. On x86_64 it is OVMF's
SMM build, which QEMU runs with `-machine smm=on` and its variable store behind SMM
(`-global driver=cfi.pflash01,property=secure,value=on`). A host with no such pair fails the case
before any boot, naming the paths it tried; a pair built without Secure Boot boots every image, so
the first three boots fail, each naming the firmware and where to find one that enforces it
([docs/build-system.md](../docs/build-system.md) § QEMU and Firmware). The case never passes on a
firmware that does not refuse. A boot is judged as the `signing` case judges one, with a deadline
of three minutes; every boot is made whatever another's outcome. Every boot's serial log is saved
as `target/xtask/test/secureboot/<arch>/<boot>.log`, beside the keys and images. The images are
packed again from the sysroot in the layout they had, with the recorded harness's bundle, whatever
the outcome.

The case builds nothing. It needs sbsigntools (`sbsign`, `sbverify`), `openssl` and
virt-firmware's `virt-fw-vars` on the host, and a populated sysroot:

```sh
cargo xtask build [--arch x86_64|riscv64] [--release]
cargo xtask test secureboot [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

#### The `hotplug` case

Check devmgr's PCI Express hotplug add and removal paths, native and through acpid, and its bind of
a hot-added disk from the drivers directory, on either arch. Stages the `hotplug-check` fixture's
recipe ([services/hotplug-check/README.md](../services/hotplug-check/README.md)) from
`config/svcmgr/tests/` into `config/svcmgr/services/` and the `test-dma` class file from
`config/devmgr/tests/` into `config/devmgr/classes/`, and repacks the disk images in the layout they
have. It boots the current sysroot headless, with two empty `pcie-root-port`s (`-device
pcie-root-port,id=hotplug-port,chassis=1,slot=1,addr=0x1c` and `-device
pcie-root-port,id=hotplug-disk-port,chassis=2,slot=2,addr=0x1d`) and a QMP socket:

1. on x86_64 only, under the machine's default, the firmware's ACPI PCI hotplug, whose `_OSC`
   withholds native hotplug control: devmgr must log the slot `firmware hotplug: _OSC control`,
   and the cycle of step 2 runs with the firmware's removal: devmgr's removal lines on its eject
   request, then acpid's `ejected (_EJ0) once devmgr removed 1 functions`;
2. under native control (on x86_64 with `-global
   ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off`, so `_OSC` grants it; on riscv64 the
   `qemu-virt.platform` key grants it once devmgr has read the table): once devmgr logs the slot
   `managed (native control by` and the fixture logs `[hotplug-check] READY for the hot-added
   device`, it hot-adds QEMU's `edu` device behind the first port (QMP `device_add`,
   `dma_mask=0xffffffff` as the test devices' `edu` has). Once the fixture logs `[hotplug-check]
   READY for the removal`, it removes the device (QMP `device_del`) and waits up to a minute for
   QEMU's `DEVICE_DELETED` event, then for devmgr's removal lines in their order and the fixture's
   `WITHDRAWN at ordinal 0` line; it then hot-adds the device again and waits for the fixture's
   `[hotplug-check] PASS` line. It then adds a raw block node over a zero-filled 1 MiB image (QMP
   `blockdev-add`) and hot-adds a `virtio-blk-pci` on it behind the second port and the IOMMU
   (`iommu_platform=on`) with no MSI-X vectors (`vectors=0`), and passes once devmgr logs `[devmgr]
   virtio-blk: binds PCI`, `virtio-blk: boot tier not granted from the drivers directory` (the
   drivers directory's copy, at the auxiliary tier) and `[devmgr] virtio-blk: Wired interrupt, 1
   vector(s)` (the line of the disk's `INTx` pin) and the driver logs `[virtio-blk] ready, entering
   service loop`.

Then two storage boots on the split-data layout, under native control, with the disk-mode recipe
(`hotplug-check-disk.svc`) staged alone:

3. the data disk (`disk-data.img`) behind the first port from boot: the host removes it (QMP
   `device_del`), requires devmgr's removal lines and vfsd's `disk N: removed; tearing down its
   mounts`, adds it again (`device_add` of a `virtio-blk-pci` on the kept block node); once the
   fixture logs `MOUNTED /data on the re-added disk`, it adds a raw block node over a copy of
   `disk-data.img` taken before the boot (`target/xtask/hotplug-tie-disk.img`, removed after
   the boot) and a `virtio-blk-pci` on it behind the second port, with the data disk's
   properties; it then requires the fixture's `PASS`, vfsd's `FATAL: root filesystem lost`,
   svcmgr's `critical service unrecoverable: vfsd; initiating graceful shutdown`, and QEMU's exit;
4. the boot disk behind the first port and the data disk on a slot of its own: the host removes
   the boot disk and requires the same last three.

It kills QEMU after each boot, then removes the staged files and repacks the images in that layout
again, whatever the outcome. [docs/testing.md](../docs/testing.md#pci-express-hotplug-hotplug-case)
§ PCI Express hotplug lists what the fixture checks.

It requires a populated sysroot:

```sh
cargo xtask build [--arch x86_64|riscv64]
cargo xtask test hotplug [--arch x86_64|riscv64] [--cpus N] [--mem MIB]
```

Each boot to its markers is bounded by five minutes, and the fixture's verdict and the disk's bind
by three minutes after their hot-add. The boots are the hotplug device cell of the local and release
host runs ([docs/testing.md](../docs/testing.md#coverage-tiers) § Coverage tiers).

---

### `cargo xtask crypto-vectors`

Regenerate the reference vectors of `shared/crypto/testkit` with OpenSSL, or check that the
checked-in files regenerate byte-identically.

```
cargo xtask crypto-vectors [--check]
```

The command builds and runs the testkit's `crypto-reference-vectors` binary for the host, which
drives the `openssl` command found on `PATH`
([shared/crypto/testkit/README.md](../shared/crypto/testkit/README.md)). Without `--check` it
writes every file under `vectors/reference/` (`ed25519.json`, `sha512.json`, `shake.json` and
`ml_dsa_65.json`); with it, it writes nothing and fails, naming each file, unless every one
regenerates byte-identically. xtask does not depend on the testkit.

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

A repository has one scratch directory, `<cache>/seraph-compare-images/<name>/`, `<cache>` being
`XDG_CACHE_HOME`, else `~/.cache`, and `<name>` the path of the repository's git common directory
with each byte but an ASCII letter, digit, `.` or `_` written as `-` and two hex digits. Every
checkout of the repository shares it, and one run at a time holds it, by a lock on its `lock` file;
a second run waits, and Ctrl+C ends its wait. Both commits are built in its scratch worktree,
`tree/`, which the command adds with `git worktree add --detach` and reuses: it checks each commit
out there, removes every untracked file but `target/`, and runs that commit's own
`cargo xtask clean` and `cargo xtask build --skip-lints --arch <a> [--release]` once per cell,
moving each built sysroot to
`<base|head>/<arch>-<profile>/` beside it. One path serves both commits because a build embeds
absolute source paths (the panic locations of the `-Z build-std` crates under
`target/seraph-toolchain/`), so builds in two checkouts never compare equal. The scratch
worktree's `target/` is kept as a cache, so a later comparison rebuilds only what changed, from
any checkout; the first one builds every cell from scratch.

Each build is the commit's own. The scratch directory is outside the checkout, whose
`.cargo/config.toml` Cargo would merge into every build below it, and the command refuses to run
when a directory above the scratch worktree holds a Cargo configuration other than Cargo's home's.
Each nested `cargo xtask` runs
without the variables the outer `cargo run` and the rustup proxy set: `CARGO` and each `CARGO_*`
but `CARGO_HOME`, `RUSTUP_TOOLCHAIN` (which outranks the commit's `rust-toolchain.toml`),
`RUST_RECURSION_COUNT`, and each variable set by the `[env]` table of a Cargo configuration the
outer build read (the checkout's and those above it, and Cargo's home's), such as
`RUST_TARGET_PATH`, which names the commit's target specifications. Removing a checkout leaves
the shared scratch directory; `git worktree remove --force <scratch>/tree`, then removing
`<scratch>`, reclaims it.

Each file of a cell's two sysroots is compared by its format:

| File | Compared parts |
|---|---|
| ELF image | The type, machine, flags, and entry of the file header; each program header but its file offset, with the bytes of each `PT_LOAD` segment past the file header (whose section-table fields locate data no loader maps); each section that is allocated or is a note, its type, flags, address, size, and bytes, since the loaders read `.note.seraph.*` sections by name; the descriptor of each GNU build-id note masked first, since the linker computes the id over the symbol tables and debug information too and nothing reads it |
| PE image (`boot.efi`) | The headers, the COFF link time stamp and the checksum masked; each section, the debug directory and the data its entries point to masked: the linker writes the time of the link there, and no UEFI loader and no code of the image reads them; the descriptor of a GNU build-id note is masked as in an ELF image (the riscv64 bootloader's flat binary carries one) |
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

### `cargo xtask ktest-timing`

Read ktest boot logs saved by `run --runs --save-logs` and report their wall times: the
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
nearest function symbol and the offset into it. An installed image other than the kernel and the
bootloader is stripped, so the command reads the image's own symbols when it has them (the
kernel), and otherwise the symbols store's file of the image's build id, refused unless that file's
build-id note matches the image's ([docs/build-system.md](../docs/build-system.md#symbols-store) §
Symbols Store). With `--log`, the addresses are those of the crash reports in a serial log. Use
cases are in [docs/testing.md](../docs/testing.md#troubleshooting) § Troubleshooting.

```
cargo xtask symbolize --binary PATH [--bias HEX] [--symbols DIR] ADDR...
cargo xtask symbolize --kernel [--bias HEX] ADDR...
cargo xtask symbolize --log FILE [--symbols DIR]
```

| Option | Default | Description |
|---|---|---|
| `--binary` | | The ELF image the addresses fall in: a sysroot binary, or its build output under `target/` |
| `--kernel` | | Resolve against the sysroot's kernel image, `sysroot/esp/EFI/seraph/kernel` |
| `--bias` | `0` | The image's load bias in hex: for a userspace process its creator's log line (procmgr `spawn image bias=0x… (<argv0>)`, init `init: <svc> image bias=0x…`, and, for init itself, the kernel's `init: PIE bias=0x…`), for the kernel the KASLR slide from its serial-only `kaslr: slide=` line (`0` in a boot authored with `mkdisk --knob nokaslr`) |
| `ADDR...` | (required without `--log`) | Runtime addresses, in hex (`0x` optional) |
| `--log` | | A serial log: symbolize every crash-report block in it (below) instead of `ADDR...` |
| `--symbols` | the build's `symbols/` | The symbols store to read in place of the build's, such as a release's symbols archive unpacked. With `--log`, the images are the store's own files named by its manifest, and the sysroot is not read |

Each address's first line is `<address> (image <address less bias>): <resolution> [<source>]`
(the image address shown only when the bias is not `0`), where the source is the one used; a
`debug-info` resolution goes on to one line per inlined caller:

| Source | Resolution |
|---|---|
| `debug-info` | `<function> at <file>:<line>[:<column>]`, followed by one `    inlined into <function> at <file>:<line>[:<column>]` line per caller the frame is inlined into, each with the position of its call |
| `symbol-table` | `<symbol>+<offset>` |
| `unresolved` | `??`: neither source covers the address |

Names are demangled. A frame prints only what its DWARF gives: `??` for an unnamed function, and
`<function> at <file>` without a line, or a bare `<function>` without a file. An image with no DWARF
at all prints a note naming the symbol-table fallback first. With `--binary` on a stripped image,
the command first prints `<binary>: symbols from <store file> (by its build id)`. An address below
the bias, an unreadable file, or a file that is not an ELF image fails the command; a compressed
debug section is refused.

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
  symbols: <the image's own | symbols/<build-id>.elf (by the image's build id)>
  <key>=<value>
  ip=<address>  <resolution> [<source>]
  frame.<n>=<address>  <resolution> [<source>]
  …
end <id>
```

The `symbols:` line reads `  symbols: the image's own` or
`  symbols: symbols/<build-id>.elf (by the image's build id)`. When the symbols cannot be found, a
`  not symbolized: <reason>` line takes its place: the image carries no symbols and no build-id
note; the image carries no symbols, and the symbols store has no `<id>.elf`; or the store's
`<id>.elf` has another build id, so it holds another image's symbols.

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
none. `run --runs` writes the same report beside each log it keeps.

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
§ Coverage tiers states still names code, a file, or a directory in the tree, that every
`cargo xtask` command line names a command, case and option the command table has, and that the
documents stating the case registry state it as it is; whether a passage is a summary, or any other
statement matches the code, is the pre-merge review's.

| Rule | Level | Check |
|---|---|---|
| `md-columns` | error | Every line of a tracked `.md` fits the column limit in [docs/coding-standards.md](../docs/coding-standards.md) § Markdown, with the exemptions that section lists (table rows; single link, image, badge, or URL constructs; YAML front matter). |
| `src-header` | error | Every tracked `.rs`, `.ld`, `.S`, `.sh`, `.yml`: the SPDX line first (after a shebang in `.sh`; on line 2, after `/*`, in a block-comment `.ld`); exactly one blank line, then the path line; for Rust, exactly one blank line, then the `//!` block before any `#![` attribute, per [docs/coding-standards.md](../docs/coding-standards.md) § File Headers. |
| `md-summarized-by` | error | Every authoritative document ends with `---` and a `## Summarized By` section holding `None` or a non-empty list of links, each resolving to a path inside the repository (no external URL, in-page-only anchor, or `..` past the root), per [docs/documentation-standards.md](../docs/documentation-standards.md) § Backlinks and Change Propagation. |
| `md-backlink-forward` | error | Every `## Summarized By` entry names a tracked document that links this one. |
| `md-summarized-by-order` | error | The `## Summarized By` entries are sorted by the repository path each link resolves to, byte by byte, and none is listed twice. |
| `md-summarized-by-label` | error | Each `## Summarized By` entry for a `README.md` is labelled with its repository path, and each other entry with the linked document's `# Title`. |
| `md-reachable` | error | Every authoritative document is reachable by links from the root `README.md`; the root README links every `docs/*.md` and every other README links each document in its own `docs/`, per [docs/documentation-standards.md](../docs/documentation-standards.md) § Discoverability and Linking. |
| `md-coverage-symbols` | error | Every name the surface list of [docs/testing.md](../docs/testing.md) § Coverage tiers states resolves: from the paragraph starting `**Boundary surface.**` up to the one starting `**Repeat count.**`, each code span naming an item, field path, or `_*` family, and each alternative of the `S`, `M`, and `D` screen variables (groups expanded, character classes kept), matches as a whole word in the code of a tracked Rust source outside `xtask/` with `//` comments stripped, or, from the paragraph starting `**Device surfaces.**` on, in that of one inside `xtask/` other than the lint's own `src/commands/lint_docs/`; each listed `.rs` path (`*` within one component; a bare file name in any directory) names a tracked file; and each listed directory, written with a trailing `/` (`*` within one component), has a tracked file beneath it. |
| `md-test-cells` | error | The documents that state the case registry of `cargo xtask test` (`src/commands/test/cases.rs`) state it as it is: the Cases table of § `cargo xtask test` has one row per case, equal to its registry entry (architectures with their boots, bundle, cell, case options); each case has a ``#### The `<case>` case`` section here and a heading naming ``(`<case>` case)`` in [docs/testing.md](../docs/testing.md) § Gating; and the cell table of docs/testing.md § Coverage tiers (the table whose first column is `Cell`) lists each case once, a CI case in its tester's row and a host-run case in a row of its own, on the architectures the registry runs it on (a parenthesis after the case naming them when they are fewer than the row's). |
| `xtask-commands` | error | Every `cargo xtask` command line resolves against the command table (`src/cli.rs`): in every tracked `.md` but the per-tag release notes `docs/releases/v*.md`, in code spans and fenced blocks, and on every line of the `.yml`, `.sh`, `.js` and `.json` files under `.github/` and `.claude/`. Its literal words name a command and each sub-command level, a fixed-value first positional (the case of `test`) names one of its values, and each `--option` is one of the command it resolves to, up to a positional that takes the rest of the line (the commands of `orch grant set`), which the rule does not read; a placeholder where a sub-command stands checks the options after it against every command below. A command line ends at the end of its code span or line (a trailing `\` continues it), a shell separator, a redirection, or a `#` comment; in a `.js` or `.json` file, at a quote. |
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
| `pr-validation` | error | The body has a `## Validation` section that names a validated head: the first word of that section that is a commit hash in the clone, the words of a quoted `compare-images` verdict line or report path aside, since they name the base commit before the head (docs/conventions.md § PR-body checklist discipline). |
| `pr-validated-head` | error | The validated head is the PR head; or it is a commit of the branch (one the head holds and the base branch does not), the section says the delta since it is documentation or comments only (a phrase that pairs `only` with comments, Markdown, or documentation, such as `comment-only`, `Markdown only`, or `only in comments`, not after a `not` within three words and outside a template placeholder `<…>`; whether the phrase is about the delta stays with the auditor), and `git diff <validated> <head>` alters, Markdown (`*.md` in any letter case) aside, only comment lines and no file a build embeds ([docs/testing.md](../docs/testing.md) § Coverage tiers). A binary change, a mode change, and any non-blank line of a file type whose comment syntax the command does not know (it knows Rust, TOML, YAML, and shell) count as changes. When a merge of the base branch lies between the two heads, the command compares the PR's own change at each, `git diff <merge base> <validated>` and `git diff <merge base> <head>`, as multisets of changed lines per file, whitespace included, instead of the delta: they must differ only in comment or Markdown lines and in no file a build embeds, two binary changes agree only when their `index` lines match (the same blobs before and after, and the same mode), a change to a final newline alone is a change, as is a different mode for a file the PR adds or deletes at both heads (an added or deleted file is otherwise judged by its lines, so a file of comments alone stays comment-only), each difference is reported with the head it stands at; a line the PR reordered or moved within its own files since the validated head, which the multisets cannot see, is read from `git diff <validated> <head>` over those files less the sync's incoming diff, and a code line of it in a file whose own change compares equal is reported as moved or reordered; and the section must say the delta is documentation or comments only when the two differ at all. |
| `pr-validated-sync` | warning | No merge of the base branch lies between a validated head that passes `pr-validated-head` and the PR head. After one the body states that the incoming diff touches none of the PR's files, or that its change to them is comment-only (§ Syncing with `master`, which judges the incoming diff restricted to the PR's files); a reader decides the overlap and the kind of that restricted diff, the command cannot. |
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
| `gate-includes-master` | error | The base branch's tip is an ancestor of the PR head; or the two have one merge base, the base branch's change since it (`git diff --name-only --no-renames`, a rename naming both its paths) names no file the PR's own change from it names, and GitHub reports the PR `MERGEABLE` (docs/conventions.md § Syncing with `master`); `UNKNOWN`, before GitHub has computed it, asks for the gate to be run again. The command prints which case held on a `master:` line: `contains`, `disjoint` with the number of commits the head lacks, `overlap`, or the number of merge bases. |
| `gate-base-green` | error | For a head that does not contain the base branch's tip, the tip's own CI run has finished green: the newest `build-test.yml` run on the push of the tip commit succeeded (`gh run list --commit`). While it is red or has not finished, only a head that contains the tip merges (docs/conventions.md § CI Gating). A tip with no run, a cancelled or skipped run, and a state that cannot be read are errors. |
| `gate-base-fresh` | error | The clone's `origin/<base>` is the base branch's tip on GitHub (`gh api`), since the two rules above read that ref: a stale one is refused with the advice to `git fetch origin`. |
| `gate-audit-not-run` | error | The last run record for the PR head is not a run of the reviewer alone (`audit_verdict` `NOT RUN`): the audit is still owed at that head, as an `audit` record with a greater `stats.run`. |
| `gate-review-record` | error | The last run record for the PR head in `target/xtask/review/pr<N>/` is well-formed and has `AUDIT PASS`, no failed agent, and the reviewer verdict `READY TO MERGE` (or, in a record of the earlier form, `NON-BLOCKING ISSUES ONLY`). The last run at a head is the record there with the greatest `stats.run`; an earlier passing run does not count. When that record is an `audit` record that completes a run of the reviewer alone (the latest `NOT RUN` record at the head with only `audit` records after it), that run must have no failed agent and a passing verdict too. Every record at the head must be well-formed, since a malformed one cannot be placed, and two with one `stats.run` are refused. A record is at the head when its name states the head's first digits; one whose `stats.head` names another commit is refused. |
| `gate-added-files` | error | The files the PR adds can be read from the clone, which the next rule needs. |
| `gate-release-approval` | warning | The PR adds no `docs/releases/v<X>.<Y>.<Z>.md`. One that does is the release PR of § Release Production, whose merge needs the maintainer's approval (§ Pre-merge review); the command cannot read an approval, so it names the PR for its reader. |
| `gate-findings-recorded` | warning | A record of the earlier form with the verdict `NON-BLOCKING ISSUES ONLY` leaves no finding on the surface that needs a reader: one an Issue had to record (a class other than `style`, or a MUST violation), or one of any class whose `status` is `contested`. When the last record is an `audit` record that completes a run of the reviewer alone, that run's verdict and findings count too. The reader confirms each counted finding is recorded and none is contested; the command cannot. |
| `gate-defects-recorded` | warning | No defect-form record of the PR lists a defect off the surface (`recorded`). The reader confirms that each one it counts is recorded on its Issue before the merge (§ Findings); the command cannot. |

The command does not judge what needs a reader: whether the body's claims match the diff, whether
an acceptance item is delivered, and which local host runs the change owes. Those stay with the
pre-merge review's audit.

### `cargo xtask review-ledger`

Validate the saved run records of a review and build its ledger: the findings a later run must
not re-raise ([docs/conventions.md](../docs/conventions.md) § Ledger).

```
cargo xtask review-ledger <N> [--check]
cargo xtask review-ledger --release <X.Y.Z> --from <previous tag> [--file <path>]...
```

With a pull request's number it checks every run record of `target/xtask/review/pr<N>/` against
the record shape below, then writes `ledger.json` beside them. A record that departs from the
shape fails the command, which then writes nothing, so the ledger and the merge gate read only
what they expect. With `--check` it validates alone and writes nothing.

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

A `full` or `delta` record whose `audit.sections` holds a section whose name contains
`auditor-only` or `completing-audit`, in any letter case, is `error record-run-kind`: those are
the checks of the auditor-only run and of the audit that completes a run of the reviewer alone,
which only an `audit` record's run kind selects (`.claude/agents/pr-auditor.md` steps 2a, 11
and 12), so the audit of that run with the reviewer is run again with the run-kind line
`Run kind: with-reviewer` (`.claude/skills/pr-review/SKILL.md` § The record).

The ledger is a sorted list without duplicates of each record's `recorded` and `dropped`
findings, its `contested` findings, and, in an earlier-form record whose verdict is
`NON-BLOCKING ISSUES ONLY`, all its `findings`. Each entry carries the finding's fields and
`run`, the first eight digits of the head of the run that reported it.

With `--release` it prints the release review's ledger as JSON on stdout: the entries of every
pull request a first-parent merge `Merge pull request #N` of `<previous tag>..HEAD` names, and
those of the release's own records in `target/xtask/review/release-v<X.Y.Z>/`, sorted and
without duplicates, limited to the files `--file` names when it is given. A release record's
finding the workflow left undecided (one in its `undecided` list, or a `contested` one, whose
refuters split, in its `findings`) enters only once the maintainer's decision is saved on it as
`ruling`. Only run records are read (`<mode>-<head>[-<n>].json`); a pull request without
records adds nothing. A record that is not a JSON object fails the command, which then prints no
ledger; the record shape above is not applied, since a release record has its own and an older
pull request's record has the form of its time. The count goes to stderr, so stdout holds the
JSON alone.

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
    (--milestone <title> | --unscheduled --reason <hardware|not-possible|undecided>)
```

The command refuses a filing without a class label, without a subsystem label, or without a
milestone decision. `--unscheduled` files an Issue without a milestone, which
[docs/conventions.md](../docs/conventions.md) § Milestones allows only for an Issue that cannot
be worked on now, and needs `--reason`: `hardware` (it needs hardware the project does not
have), `not-possible` (it is not possible yet) or `undecided` (whether it belongs in the project
is itself undecided). The body states the same reason in a line that begins
`No milestone: <reason>`, the reason as `--reason` names it and the rest of the line saying why;
the command refuses an `--unscheduled` filing whose body has no such line or one naming another
reason, and a filing under a milestone whose body has one. It refuses a rolling follow-up Issue
(a title ending `: defects found by review`) under anything but the current milestone, the
lowest-versioned open one, which it reads from GitHub, and one whose title an open Issue of the
current milestone already carries: the scope has its rolling Issue there (§ Follow-up Issues).
A rolling Issue of an earlier milestone carries the same title and does not count. After filing
it reads the Issue back and fails when a label or the milestone was not applied, naming what is
missing.

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

### `cargo xtask capture-acpi`

Capture the ACPI tables of one QEMU configuration into the `shared/aml` fixtures
([shared/aml/README.md](../shared/aml/README.md) § Fixtures). Boots the firmware alone, headless,
on a blank 1 MiB disk, in the tree's launch of the configuration's architecture with the test
devices attached, 4 vCPUs and 512 MiB, plus the devices the configuration adds. Once the
firmware prints its first boot-option line (`BdsDxe: ` from OVMF, `[Bds]Booting ` from the
riscv64 firmware), by which point it has installed the tables QEMU generated, the command stops
the guest and saves its RAM over QMP (`stop`, then `pmemsave`), and QEMU quits.

It then finds every RSDP in the RAM image (the signature on a 16-byte boundary, the checksum
valid, and from revision 2 the extended checksum too), walks its XSDT, or its RSDT when it has
no XSDT, checking every table's checksum, and takes the DSDT from the FADT's `X_DSDT`, or its
32-bit `DSDT` when the FADT is too short for `X_DSDT` or it is zero. Every RSDP whose walk
succeeds must give the same tables. It replaces the `.aml` files of the output directory with
`DSDT.aml` and the SSDTs in XSDT order (`SSDT1.aml`, `SSDT2.aml`, ...), and writes
`capture.txt`: the command, the QEMU version, the firmware image's file name, the QEMU
arguments with host paths replaced by placeholders, and the signatures of the root table's
entries.

```sh
cargo xtask capture-acpi --config <configuration> [--out DIR] [--timeout SECS]
```

| Option | Default | Description |
|---|---|---|
| `--config` | (required) | The configuration (below) |
| `--out` | `shared/aml/fixtures/<config>` | The directory the tables are written to |
| `--timeout` | `600` | Seconds to wait for the firmware's boot-option line |

| Configuration | Added to the launch |
|---|---|
| `x86-default` | Nothing |
| `x86-rootport` | `-device pcie-root-port,id=rp0,chassis=1,addr=0x1c` |
| `x86-rootport-native` | The `x86-rootport` root port and `-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off` |
| `riscv64-rootport` | `-device pcie-root-port,id=rp0,chassis=1` |

Needs no sysroot. The boot is a small one of the host launch rules (below). The command fails
when no RSDP's walk succeeds, when two give different tables, and on a QMP error or a timeout:
the boot-option wait, 120 s for `pmemsave`, and 30 s for QEMU to quit.

---

## Host launch rules

The worktrees of one checkout share one host. The commands that load it apply its launch rules
themselves, from `src/host_lock.rs`, before they start: `build`, `clean`, `crypto-vectors`,
`compare-images` and `test` without a case or a cell (the unit tests) as builds
(`CliCommand::build_host` in `src/cli.rs` names them); `run`, `capture-acpi`, and `test` with a case
or a cell as boots, each boot admitted as above (the `shutdown` case admits once for its boots,
which it runs one at a time). The `signing` case, which compiles its revoking bootloader before it
boots, is admitted as a build for that compile and then each boot as a boot.

A boot is small when each QEMU it starts has at most 4 vCPUs and it starts at most 3 side by
side (`run --runs` starts `min(--parallel, --runs)` per wave). Any other boot needs the host
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
| `--timing` | Boots | A timing-sensitive measurement: beside no other QEMU, under the load limit of 10 of a boot that needs the host to itself, with builds refused while it runs. |
| `--grant <HOLDER>` | Boots | Boot under the exclusive grant of HOLDER. |

The load is the host's `getloadavg` (`/proc/loadavg` on Linux); a host that reports none is not
refused on it. On a GitHub Actions runner (`GITHUB_ACTIONS=true`) the checks are skipped with one
printed line: each CI job is its own host.

---

## Pattern syntax

Every regular expression xtask matches, those `run` takes (`--pass`, `--fail`,
`--fail-also`, `--require`) and those its checks compile (`commit-check`, `pr-check`, `lint-docs`,
`ktest-timing`), runs on xtask's own engine in `src/regex/`: a
Pike VM over the syntax below. The match reported is the leftmost-first one: the earliest start,
and at that start the alternative and the repetition count a backtracking engine would try
first. A search does at most a constant amount of work per instruction of the compiled pattern
per character of the text, whatever the two hold, so no text makes a match run long; a pattern
compiles to at most 10000 instructions (`MAX_INSTS`).

| Construct | Matches |
|---|---|
| `x` | The character, for any character but `\ . + * ? ( ) \| [ { ^ $` |
| `\x` | `x`, for any ASCII punctuation character `x` but `<` and `>` |
| `\n`, `\r`, `\t` | Newline, carriage return, tab |
| `.` | Any character but newline |
| `[...]`, `[^...]` | One character of the set, or one outside it with `^`: characters, ranges (`a-z`), escapes, and the classes below; `]` first and `-` first or last are members |
| `\d`, `\w`, `\s` | An ASCII digit; an ASCII letter, digit or `_`; a Unicode `White_Space` character |
| `\D`, `\W`, `\S` | Any character the lower-case class does not match |
| `^`, `$` | The start, the end of the text (not of a line) |
| `\b`, `\B` | A position with a `\w` character on exactly one side; any other position |
| `a\|b` | `a`, or else `b` |
| `(...)` | A capture group, numbered from 1 by its `(` |
| `(?:...)` | A group that captures nothing |
| `(?i)`, `(?-i)` | From here to the end of the enclosing group, ASCII letters match either case, or only their own |
| `(?i:...)`, `(?-i:...)` | The same, within the group |
| `*`, `+`, `?` | 0 or more, 1 or more, 0 or 1 of the preceding item, as many as lead to a match |
| `{n}`, `{n,}`, `{n,m}` | n, at least n, n to m of the preceding item (n and m at most 1000), as many as lead to a match |
| `*?`, `+?`, `??`, `{n,}?`, `{n,m}?` | The same, as few as lead to a match |

Anything else is refused with its reason and its byte offset in the pattern: a back-reference, a
look-around, a named group, a Unicode class (`\p{..}`), the word-start and word-end assertions
(`\<`, `\>`), a nested class, a class set operation (a doubled `&`, `-` or `~` in a class), a
flag other than `i`, a repetition of a repetition (`a**`), and groups nested more than 64 deep.
Where the syntax overlaps that of the Rust `regex` crate it means the same, except that `\d`,
`\w` and `\b` are ASCII only and `(?i)` folds ASCII letters only.

---

## Command-line parsing

xtask parses its command line with its own parser in `src/argparse/`. The command table is
`src/cli.rs`: each command's arguments are a struct declared with `args!`, each command with
subcommands an enum declared with `subcommands!`, and each closed set of values an enum declared
with `value_enum!`. A field's name, type, `#[arg(..)]` options and doc comment state the
argument once: the macro builds the struct, its argument specifications, and the code that types
the parsed values into it.

| Field | Argument |
|---|---|
| `bool` | A flag |
| `T` | One value; required unless it has a default |
| `Option<T>` | One value, optional |
| `Vec<T>` | Any number of values, each occurrence adding to them |
| `#[command(flatten)] S` | The arguments of the `args!` struct `S` |
| `#[command(subcommand)] E` | One of the commands of the `subcommands!` enum `E` |

A field without `long` is a positional. The options are `long`, `value_name`, `default_value`,
`default_value_t`, `value_delimiter`, `value_parser` (a `fn(&str) -> Result<T, String>`),
`required`, `requires`, `conflicts_with`, `conflicts_with_all`, `required_unless_present`,
`required_unless_present_any`, `trailing_var_arg`, `allow_hyphen_values` and `hide`, with the
meaning clap 4's derive gives them; a `value_enum!` variant takes `#[value(name = ..)]`. A
command's name is its variant's name in kebab case, and the first paragraph of a doc comment is
the short help, the whole comment the long help (`--help`).

The parser reads a command line as clap 4.6 read it, and prints its help and its errors as clap
printed them without styling: the same subcommands, arguments, values, defaults, conflicts and
requirements; the same help screens, byte for byte; the same error kinds, with the same message
up to its first blank line; and exit status 0 for help and 2 for an error. An error's `Usage:`
line is the command's own usage line, without the arguments given or a suggested one, and an
error prints no `tip:` lines. An argument that is not valid UTF-8 is refused with clap's
`InvalidUtf8` error wherever it stands, a path value among them, which clap passed on as its
bytes.

`src/argparse/reference/` holds the evidence: every help screen of the table (91), and 7374 command
lines with their outcome (the command and the values parsed, or the error's kind and message),
recorded from clap 4.6 before the parser replaced it. `cargo xtask test` parses each command line
and prints each screen through the table, and fails on any difference. A change to the table that
changes a recorded outcome on purpose, a new command or argument among them, adds the command lines
that exercise it to `cases.txt` and runs `XTASK_BLESS_REFERENCE=1 cargo xtask test`, which rewrites
every screen and outcome from the current table; the diff of `reference/` is the change to the
command line, for the review to read.

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
| [docs/memory-model.md](../docs/memory-model.md) | Randomized kernel layout the `kaslr` case checks; RISC-V paging-mode ceiling behind `--riscv-mmu`; x86-64 paging depth behind `--x86-paging` |
| [docs/userspace-memory-model.md](../docs/userspace-memory-model.md) | PIE image placement and the per-spawn ASLR bias used with `--gdb` and `symbolize --bias` |
| [docs/storage.md](../docs/storage.md) | GPT role-GUID discovery of the data partition the disk image carries |
| [docs/testing.md](../docs/testing.md) | Harnesses, markers, and the host-driven boot tests the `test` cases run; the Coverage tiers surface list `lint-docs` checks; the Troubleshooting guide `symbolize` serves |
| [services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md) | The debug port `--debug-port` attaches and the `debug-port` case drives |
| [services/gdbstub/README.md](../services/gdbstub/README.md) | The GDB stub `--debug-target` stages and the `debug-port` case's GDB stub boot drives |
| [services/devmgr/docs/hotplug.md](../services/devmgr/docs/hotplug.md) | The PCI Express hotplug the `hotplug` case drives, native and through acpid |
| [docs/coding-standards.md](../docs/coding-standards.md) | Lints `build` and `test` enforce; the Markdown and file-header rules `lint-docs` checks |
| [docs/documentation-standards.md](../docs/documentation-standards.md) | Document hierarchy and backlink rules `lint-docs` checks |
| [targets/README.md](targets/README.md) | Custom target specs |

---

## Adding a new command

1. Add a variant to `CliCommand` in `src/cli.rs` with a corresponding `args!` struct, and name
   it in `CliCommand::build_host`: a command that compiles takes `HostArgs` and is admitted there
   as a build. Add its command lines to the reference corpus (§ Command-line parsing).
2. Create `src/commands/<name>.rs` with `pub fn run(ctx: &Context, args: &NameArgs) -> Result<()>`,
   or add a `pub fn run_<name>` to the module that holds its sibling commands (`pr_check`,
   `review`, and `issue` each hold two).
3. Add a match arm in `src/main.rs`.
4. Re-export the module in `src/commands/mod.rs`.

A new host-driven QEMU test is a registry case (`src/commands/test/cases.rs`), not a command.

---

## Summarized By

[README.md](../README.md), [RISC-V UEFI Boot](../core/boot/docs/riscv-uefi-boot.md),
[Kernel Entropy Subsystem](../core/kernel/docs/entropy.md),
[core/ktest/README.md](../core/ktest/README.md), [Architecture Overview](../docs/architecture.md),
[Build System](../docs/build-system.md), [Coding Standards](../docs/coding-standards.md),
[Memory Model](../docs/memory-model.md), [Testing](../docs/testing.md),
[programs/terminal/README.md](../programs/terminal/README.md),
[rootfs/README.md](../rootfs/README.md),
[services/gdbstub/README.md](../services/gdbstub/README.md),
[shared/aml/README.md](../shared/aml/README.md)
