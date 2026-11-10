// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/cli.rs

//! Clap derive structs for the xtask CLI.
//!
//! Add a new top-level command by adding a variant to `CliCommand` and a
//! corresponding `Args` struct below, then handle it in `main.rs`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::arch::Arch;
use crate::bundle::Harness;
use crate::disk::BlockSize;
use crate::qemu::{Iommu, RiscvMmu, X86Paging};

/// Top-level CLI entry point.
#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Seraph build task runner — invoke via `cargo xtask`"
)]
pub struct Cli
{
    #[command(subcommand)]
    pub command: CliCommand,
}

/// Available subcommands.
#[derive(Subcommand)]
pub enum CliCommand
{
    /// Build Seraph components and populate the sysroot.
    Build(BuildArgs),

    /// Launch Seraph under QEMU. Requires a populated sysroot — run
    /// `cargo xtask build` first.
    Run(RunArgs),

    /// Remove the sysroot (and optionally cargo target/).
    Clean(CleanArgs),

    /// Run Seraph unit tests on the host.
    Test(TestArgs),

    /// Launch N QEMU instances in parallel against an already-built image,
    /// classifying each run's outcome via user-supplied pass/fail regexes.
    /// Requires a populated sysroot — run `cargo xtask build` first.
    RunParallel(RunParallelArgs),

    /// Read preserved ktest boot logs (from `run-parallel --save-logs`) and
    /// print per-tier and per-cell wall times; with `--base` and `--wide`,
    /// compare two widths against their width factor; with `--baseline`,
    /// compare one log against a checked-in baseline of the same width; with
    /// `--write-baseline`, write one. Report-only: a flagged row never fails
    /// the command. See xtask/README.md for the tables and the baseline format.
    KtestTiming(KtestTimingArgs),

    /// Resolve runtime addresses in a loaded ELF image (a binary, or the
    /// sysroot's kernel) to function, file, and line from its DWARF, or to the
    /// nearest function symbol when no DWARF covers an address. Each output
    /// line names the source it used. With `--log`, print every crash-report
    /// block of a serial log with its addresses resolved against the
    /// sysroot's binaries. See xtask/README.md.
    Symbolize(SymbolizeArgs),

    /// Mirror `rootfs/` into the sysroot, re-synthesise test fixtures,
    /// and regenerate `disk.img` without invoking cargo. The mirror is
    /// authoritative over `config/`+`data/` (deletions in `rootfs/` are
    /// pruned); use `--repack-only` to pack a hand-staged sysroot verbatim.
    /// Requires an arch-tagged sysroot from a prior `cargo xtask build`.
    Mkdisk(MkdiskArgs),

    /// Compose `sysroot/esp/EFI/seraph/bootstrap.bundle` from
    /// `sysroot/services/` and repack `disk.img`. Use `--harness ktest`
    /// to run the kernel test harness; the default is `--harness init`.
    /// Requires a populated sysroot from a prior `cargo xtask build`.
    ComposeBundle(ComposeBundleArgs),

    /// Boot the terminal interactive test: launch QEMU with a QMP control
    /// socket, wait for the guest terminal's READY marker, inject a known key
    /// sequence through the virtio-input driver, and assert the echoed input
    /// and the relayed child output appear on the serial stream. Requires a
    /// populated sysroot with `terminal.svc` staged (the default boot set
    /// already includes it) and `disk.img` repacked — see xtask/README.md.
    TestTerminal(TestTerminalArgs),

    /// Boot the VMGENID snapshot-resume test (`x86_64` only): boot with a fixed
    /// generation GUID, save the guest via QMP migrate-to-file, restore it
    /// under a different GUID with `-incoming`, and assert the kernel's
    /// generation-change detection plus post-resume liveness. Requires the
    /// same populated sysroot as `test-terminal`.
    TestVmgenid(TestVmgenidArgs),

    /// Boot the KASLR randomization test: boot twice, scrape the kernel's
    /// serial-only `kaslr:` line, and assert the image slide and direct-map
    /// base differ between boots; then boot once with the `--no-kaslr` knob
    /// staged and assert the deterministic layout. Requires a populated
    /// sysroot with the ktest bundle composed (see xtask/README.md).
    TestKaslr(TestKaslrArgs),

    /// Check that a child's death reaches logd and evicts its slot: read a
    /// svctest boot's serial log for logd's `reclaim:` line naming svctest's
    /// `svctest-logd-reclaim` child. `--log` reads a saved log and boots
    /// nothing; with no log, boots the current sysroot once (svctest staged)
    /// through `run-parallel` and reads the log it saves (see xtask/README.md).
    TestLogdReclaim(TestLogdReclaimArgs),

    /// Check the crash service's report blocks in a boot's saved serial log:
    /// every block well-formed, and the `crashme` fixture's three reports
    /// present (`--expect reports`), or no block at all (`--expect none`)
    /// (see xtask/README.md).
    TestCrashReport(TestCrashReportArgs),

    /// Check that a boot whose bootloader redoes its steps 6 and 7 completes:
    /// stage the `\EFI\seraph\mapredo` test knob, boot the current sysroot
    /// once through `run-parallel`, assert the bootloader's knob line and the
    /// pass marker, and remove the knob again (see xtask/README.md).
    TestMapRedo(TestMapRedoArgs),

    /// Check the debug port's transport: stage the `debug-echo` fixture,
    /// boot the current sysroot once with `--debug-port`, exchange GDB remote
    /// serial protocol packets with the fixture over the port's TCP end, and
    /// unstage the fixture again (see xtask/README.md).
    TestDebugPort(TestDebugPortArgs),

    /// Check the GDB stub: stage it and its `gdb-target` process, boot the
    /// current sysroot once with `--debug-port`, run the host's GDB in batch
    /// mode against the port, check what it reports, and unstage both
    /// again (see xtask/README.md).
    TestGdb(TestGdbArgs),

    /// Check the mechanical documentation and source-header rules: Markdown
    /// column limit, file-header layout, `## Summarized By` shape and forward
    /// links, and document reachability from the root README. Runs in CI's
    /// host-tests job; see xtask/README.md for the rule list and levels.
    LintDocs(LintDocsArgs),

    /// Check the commits of a range against the commit-message rules of
    /// docs/conventions.md: subject form and width, Issue references and
    /// planning labels in the subject, closing keywords, attribution, and
    /// signatures. Runs in CI's host-tests job on a pull request; see
    /// xtask/README.md for the rule list and levels.
    CommitCheck(CommitCheckArgs),

    /// Check a pull request against the rules of docs/conventions.md a script
    /// can decide: its commits, its body's boxes and validated head, its
    /// milestone, and the Issues it closes or references; with `--gate`, the
    /// merge gate too. Reads GitHub through `gh` (see xtask/README.md).
    PrCheck(PrCheckArgs),

    /// Validate the saved run records of a pull request's pre-merge review
    /// (`target/xtask/review/pr<N>/`) against the record shape (see
    /// xtask/README.md).
    ReviewCheck(ReviewCheckArgs),

    /// Build `ledger.json` from the saved run records of a pull request's
    /// pre-merge review: the findings a later run must not re-raise (see
    /// xtask/README.md).
    ReviewLedger(ReviewLedgerArgs),

    /// Replace a GitHub Issue's body from a file, refusing an empty body or
    /// one that lost task-list items, keeping a backup, and verifying the
    /// edit (see xtask/README.md).
    IssueEdit(IssueEditArgs),

    /// File a GitHub Issue with the labels and milestone docs/conventions.md
    /// requires, and verify that both were applied (see xtask/README.md).
    IssueFile(IssueFileArgs),
}

// ── Build ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct BuildArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Build in release mode (default: debug).
    #[arg(long)]
    pub release: bool,

    /// Build only one component (default: all): `boot`, or the crate name
    /// of any component the build installs.
    #[arg(long, default_value = "all", value_parser = parse_build_component)]
    pub component: BuildComponent,

    /// Emit debuginfo (`debug = 2`, `opt-level = 1`) for the named
    /// component(s) only, within the active profile (default or `--release`).
    /// Comma-separated, e.g. `--debug kernel,procmgr`; names match
    /// `--component`. Only components in the current build are affected.
    #[arg(long, value_delimiter = ',', value_parser = parse_build_component)]
    pub debug: Vec<BuildComponent>,

    /// Skip `cargo fmt` and per-component `cargo check` (clippy). `cargo
    /// xtask run` sets this internally to keep the tight edit → rebuild →
    /// launch loop responsive — an unchanged tree would otherwise pay for
    /// ~2× cargo invocations per component (check + build) on every
    /// re-run. Use `cargo xtask build` when you want the full lint pass.
    #[arg(long, hide = true)]
    pub skip_lints: bool,
}

/// A component `cargo xtask build` builds: the bootloader, every component,
/// or one crate of the build's spec table (`SPECS` in
/// `xtask/src/commands/build.rs`), by its crate name. The names are read from
/// that table, so a crate added to it is accepted with no second list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildComponent
{
    Boot,
    All,
    /// A crate of the spec table, by its crate name.
    Spec(&'static str),
}

/// Clap value parser for a [`BuildComponent`]: `boot`, `all`, or the crate
/// name of a spec-table entry.
fn parse_build_component(text: &str) -> Result<BuildComponent, String>
{
    match text
    {
        "boot" => Ok(BuildComponent::Boot),
        "all" => Ok(BuildComponent::All),
        name => crate::commands::build::spec_name(name)
            .map(BuildComponent::Spec)
            .ok_or_else(|| {
                let names: Vec<&str> = crate::commands::build::spec_names().collect();
                format!(
                    "no component named {name:?}; expected boot, all, or one of: {}",
                    names.join(", ")
                )
            }),
    }
}

// ── Run ───────────────────────────────────────────────────────────────────────

// struct_excessive_bools: each bool is an independent command-line switch
// (`--gdb`, `--headless`, `--verbose`, `--second-disk-shared-line`) that clap
// maps one-to-one; they are not states of one machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
pub struct RunArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Start QEMU with a GDB server on localhost:1234 (QEMU pauses at startup).
    #[arg(long)]
    pub gdb: bool,

    /// Run without a display window (-display none).
    #[arg(long)]
    pub headless: bool,

    /// Show all serial output including pre-boot firmware noise
    /// (suppressed by default).
    ///
    /// By default, output is suppressed until the first line containing
    /// '[--------] boot:', hiding UEFI/OpenSBI debug spam. The
    /// control-sequence filter (drops xterm window manipulation,
    /// alternate-screen toggles, mouse tracking, etc.) is always on in
    /// both modes — verbose only disables the marker gate, not the
    /// filter.
    #[arg(long)]
    pub verbose: bool,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// Guest RISC-V paging-mode ceiling (riscv64 only; ignored on `x86_64`).
    /// The kernel negotiates the highest advertised mode at boot, so this
    /// selects the mode a run exercises.
    #[arg(long, default_value = "sv48")]
    pub riscv_mmu: RiscvMmu,

    /// Guest x86-64 paging depth (`x86_64` only; ignored on riscv64). Pins
    /// the QEMU CPU's `la57` property; the bootloader enables 5-level paging
    /// when CPUID reports LA57, so this selects the depth a run exercises.
    #[arg(long, default_value = "4")]
    pub x86_paging: X86Paging,

    /// Whether the machine's IOMMU is attached, with the driven `virtio-pci`
    /// devices behind it. `absent` boots the no-IOMMU variant, the no-iommu
    /// device cell of the local and release host runs (docs/testing.md
    /// "Coverage tiers"), which keeps devmgr's unconfined path covered while
    /// the attached IOMMU confines every device a driver binds.
    #[arg(long, default_value = "attached")]
    pub iommu: Iommu,

    /// Attach this image as a second disk: its own `virtio-blk-pci` device
    /// (drive `hd1`) beside `disk.img`, presenting the logical block size of
    /// the image's GPT unless `--second-disk-block-size` sets it (an image
    /// with no GPT at 512- or 4096-byte blocks needs it set). `cargo xtask
    /// mkdisk --split-data` authors `disk-data.img` for it.
    #[arg(long, value_name = "PATH")]
    pub second_disk: Option<PathBuf>,

    /// Logical and physical block size, in bytes, of the second disk's
    /// device, overriding the size read from its image (a power of two of at
    /// least 512; a size above the guest driver's 4096 stages the boot whose
    /// second device the driver refuses).
    #[arg(long, value_name = "BYTES", requires = "second_disk")]
    pub second_disk_block_size: Option<u32>,

    /// Place the second disk's device on the first disk's `INTx` line (four
    /// PCI slots past it, where both machines' interrupt routing puts it on
    /// the same line), staging the boot in which two virtio-blk devices
    /// share one line.
    #[arg(long, requires = "second_disk")]
    pub second_disk_shared_line: bool,

    /// Attach the debug port: a `virtio-console` device, which devmgr binds
    /// as the debug port, its host end a TCP server QEMU listens with on
    /// `127.0.0.1:<PORT>` (a debugger connects with `target remote
    /// localhost:<PORT>`). The console keeps the UART.
    #[arg(long, value_name = "PORT")]
    pub debug_port: Option<u16>,

    /// Stage the GDB stub for this boot, attached to the process named
    /// NAME (its argv[0]), and print the GDB command line that connects to
    /// it; the stub is unstaged when QEMU exits. Requires `--debug-port`.
    #[arg(long, value_name = "NAME", requires = "debug_port")]
    pub debug_target: Option<String>,
}

// ── Mkdisk ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct MkdiskArgs
{
    /// Target architecture — must match the existing sysroot's arch tag.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Repack `disk.img` from the sysroot exactly as it is, skipping the
    /// `rootfs/` re-mirror. Use after editing the staged sysroot directly
    /// (e.g. adding a test recipe or removing a default one): a normal
    /// re-mirror is authoritative and would restore `rootfs/`-present recipes
    /// and prune `rootfs/`-absent ones, undoing the manual staging.
    #[arg(long)]
    pub repack_only: bool,

    /// Stage the `\EFI\seraph\nokaslr` override knob so the bootloader boots
    /// the kernel at its deterministic (un-randomized) layout — for GDB /
    /// symbolization workflows. Omit to remove the knob and re-enable KASLR.
    #[arg(long)]
    pub no_kaslr: bool,

    /// Logical block size of the authored images: the unit of their GPT LBAs
    /// and the sector size of their FAT volumes. `run` and the other
    /// launchers present the disk device at the size the image's GPT has.
    #[arg(long, default_value = "512")]
    pub block_size: BlockSize,

    /// Author the data partition alone on a second image, `disk-data.img`,
    /// and only the ESP and root partitions on `disk.img`; boot the pair with
    /// `--second-disk disk-data.img`. Without it `disk.img` carries all three
    /// and a `disk-data.img` an earlier authoring left is removed.
    #[arg(long)]
    pub split_data: bool,
}

// ── TestTerminal ──────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestTerminalArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,
}

// ── TestVmgenid ───────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestVmgenidArgs
{
    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,
}

// ── TestKaslr ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestKaslrArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// riscv64 paging mode to negotiate (ignored on x86-64).
    #[arg(long, default_value = "sv48")]
    pub riscv_mmu: RiscvMmu,

    /// Guest x86-64 paging depth (`x86_64` only; ignored on riscv64). Pins
    /// the QEMU CPU's `la57` property; the bootloader enables 5-level paging
    /// when CPUID reports LA57, so this selects the depth a run exercises.
    #[arg(long, default_value = "4")]
    pub x86_paging: X86Paging,
}

// ── TestCrashReport ───────────────────────────────────────────────────────────

/// What `test-crash-report` expects of a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CrashReportExpect
{
    /// The `crashme` fixture's `vm` and `exception` reports of its main
    /// thread and its `worker` report of a spawned thread: a usertest boot
    /// with crashd staged.
    Reports,
    /// No report block: a boot of an image that stages no crashd.
    None,
}

#[derive(Parser)]
pub struct TestCrashReportArgs
{
    /// A boot's saved serial log to check (a `run-parallel --save-logs`
    /// log). Nothing boots.
    #[arg(long, value_name = "FILE")]
    pub log: PathBuf,

    /// What the log must hold beyond well-formed blocks.
    #[arg(long, value_enum, default_value = "reports")]
    pub expect: CrashReportExpect,
}

// ── TestLogdReclaim ───────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestLogdReclaimArgs
{
    /// Target architecture (the boot's; with `--log`, unused).
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// A svctest boot's saved serial log to check. With it, nothing boots.
    #[arg(long, value_name = "FILE")]
    pub log: Option<PathBuf>,

    /// Boot timeout, in seconds, for HANG classification (ignored with
    /// `--log`).
    #[arg(long, default_value = "900")]
    pub timeout: u64,

    /// Number of vCPUs to expose to the guest (QEMU -smp; ignored with
    /// `--log`).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m; ignored with `--log`).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// riscv64 paging mode to negotiate (ignored on x86-64 and with
    /// `--log`).
    #[arg(long, default_value = "sv48")]
    pub riscv_mmu: RiscvMmu,

    /// Guest x86-64 paging depth (`x86_64` only; ignored with `--log`).
    #[arg(long, default_value = "4")]
    pub x86_paging: X86Paging,
}

// ── TestMapRedo ───────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestMapRedoArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Boot timeout, in seconds, for HANG classification.
    #[arg(long, default_value = "900")]
    pub timeout: u64,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// riscv64 paging mode to negotiate (ignored on x86-64).
    #[arg(long, default_value = "sv48")]
    pub riscv_mmu: RiscvMmu,

    /// Guest x86-64 paging depth (`x86_64` only; ignored on riscv64).
    #[arg(long, default_value = "4")]
    pub x86_paging: X86Paging,
}

// ── TestDebugPort ─────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestDebugPortArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// The host TCP port the debug port is served on.
    #[arg(long, default_value = "4560")]
    pub port: u16,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,
}

// ── TestGdb ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestGdbArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// The host TCP port the debug port is served on.
    #[arg(long, default_value = "4561")]
    pub port: u16,

    /// The host GDB to run (it must debug the architecture).
    #[arg(long, default_value = "gdb")]
    pub gdb: String,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,
}

// ── ComposeBundle ────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct ComposeBundleArgs
{
    /// Target architecture — must match the existing sysroot's arch tag.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Which harness binary to use as the bundle's `init` entry.
    #[arg(long, default_value = "init")]
    pub harness: Harness,
}

// ── Clean ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct CleanArgs
{
    /// Also remove the cargo target/ directory (full clean).
    #[arg(long)]
    pub all: bool,
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestArgs
{
    /// Test a single component (default: all).
    #[arg(long, default_value = "all")]
    pub component: TestComponent,
}

/// Components that can be tested individually.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TestComponent
{
    Boot,
    Protocol,
    Kernel,
    Init,
    All,
}

// ── RunParallel ───────────────────────────────────────────────────────────────

/// Default `--fail` regex for `run-parallel`. Matches the cross-harness
/// `SOME TESTS FAILED` marker plus the kernel's death markers so a crash is
/// classified FAIL rather than HANG. `KERNEL EXCEPTION` + `FATAL:` cover the
/// hardware-trap path; `PANIC( at |: )` covers the Rust `#[panic_handler]`;
/// `entropy: SELFTEST FAIL` covers the kernel entropy self-test.
/// The benign `USERSPACE FAULT` path matches none of these.
pub const DEFAULT_FAIL_REGEX: &str =
    r"SOME TESTS FAILED|KERNEL EXCEPTION|FATAL:|PANIC( at |: )|=== WATCHDOG|entropy: SELFTEST FAIL";

/// Default `run-parallel --pass` regex: the cross-harness terminal pass
/// marker `[<harness>] ALL TESTS PASSED` (docs/testing.md § Reporting marker).
pub const DEFAULT_PASS_REGEX: &str = "ALL TESTS PASSED";

/// Default `run-parallel --fail-grace-secs`.
pub const DEFAULT_FAIL_GRACE_SECS: u64 = 10;

#[derive(Parser)]
pub struct RunParallelArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// Concurrency: number of QEMU instances in flight at once.
    #[arg(long)]
    pub parallel: u32,

    /// Total runs to perform, dispatched in waves of `--parallel`.
    #[arg(long)]
    pub runs: u32,

    /// Per-run timeout, in seconds. A run still alive at this point is
    /// killed and classified as HANG.
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Number of vCPUs to expose to each guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// Guest RISC-V paging-mode ceiling (riscv64 only; ignored on `x86_64`).
    /// The kernel negotiates the highest advertised mode at boot, so this
    /// selects the mode every run in the batch exercises.
    #[arg(long, default_value = "sv48")]
    pub riscv_mmu: RiscvMmu,

    /// Guest x86-64 paging depth (`x86_64` only; ignored on riscv64). Pins
    /// the QEMU CPU's `la57` property; the bootloader enables 5-level paging
    /// when CPUID reports LA57, so this selects the depth a run exercises.
    #[arg(long, default_value = "4")]
    pub x86_paging: X86Paging,

    /// Whether the machine's IOMMU is attached, with the driven `virtio-pci`
    /// devices behind it. `absent` boots the no-IOMMU variant, the no-iommu
    /// device cell of the local and release host runs (docs/testing.md
    /// "Coverage tiers"), which keeps devmgr's unconfined path covered while
    /// the attached IOMMU confines every device a driver binds.
    #[arg(long, default_value = "attached")]
    pub iommu: Iommu,

    /// What each guest presents for display. `headless` attaches no display
    /// adapter, so the bootloader finds no GOP and devmgr spawns no
    /// framebuffer driver; `framebuffer` keeps QEMU std VGA with no display
    /// window (`-display none`), so the framebuffer driver runs on a host
    /// without a graphical backend: the framebuffer device cell of the local
    /// and release host runs (docs/testing.md "Coverage tiers").
    #[arg(long, default_value = "headless")]
    pub display: crate::qemu::BatchDisplay,

    /// Regex marking a successful run. On match the log is discarded and
    /// the run is classified PASS. The default matches the cross-harness
    /// terminal marker `[<harness>] ALL TESTS PASSED` standardised in
    /// [`docs/testing.md`](../../docs/testing.md); override for other
    /// rootfs configurations.
    #[arg(long, default_value = DEFAULT_PASS_REGEX)]
    pub pass: String,

    /// Regex marking a failed run. On match the log is preserved as
    /// FAIL-<run>.log. Failure takes precedence over success. The default
    /// matches the cross-harness terminal marker
    /// `[<harness>] SOME TESTS FAILED` ([`docs/testing.md`](../../docs/testing.md)) plus the kernel's
    /// own death markers, so a crash classifies as FAIL rather than HANG: a
    /// hardware trap prints `KERNEL EXCEPTION` then `FATAL:`
    /// (`core/kernel/src/main.rs` `fatal()`), a Rust `panic!` prints
    /// `PANIC at`/`PANIC:` (the `#[panic_handler]`), and the scheduler's
    /// wedge detectors print a dump headed `=== WATCHDOG` (a kernel that
    /// detected its own stall is a failure, not a hang), and the entropy
    /// subsystem's boot self-test prints `entropy: SELFTEST FAIL`. The benign
    /// userspace fault path prints `USERSPACE FAULT`, which none of these
    /// match. Override with a never-matching pattern (e.g.
    /// `'$.^'`) to disable.
    #[arg(long, default_value = DEFAULT_FAIL_REGEX)]
    pub fail: String,

    /// A further regex marking a failed run, matched beside `--fail` rather
    /// than in its place, so the default's death markers still apply: a run
    /// whose log matches either is FAIL, with the same precedence and
    /// `--fail-grace-secs` kill. The framebuffer device cell passes
    /// `'framebuffer case skipped'`, the line svctest logs when no
    /// framebuffer driver runs.
    #[arg(long, value_name = "REGEX")]
    pub fail_also: Option<String>,

    /// Expose each guest's gdbstub without pausing it (QEMU `-s`,
    /// `tcp::1234`), so a wedged guest can be attached to post-hoc:
    /// `gdb -ex 'target remote :1234'`. Requires `--parallel 1` (one
    /// gdbstub port).
    #[arg(long)]
    pub debug_listen: bool,

    /// On a hard-timeout HANG, do not kill the QEMU instance: print the
    /// attach instructions and block until it is terminated externally,
    /// preserving the wedged guest for inspection (pair with
    /// `--debug-listen`). Requires `--parallel 1`.
    #[arg(long)]
    pub hold_on_hang: bool,

    /// Grace window, in seconds, after the first `--fail` match before the
    /// run is `SIGKILLed`. A kernel fault dump is multi-line and may be
    /// followed by secondary-CPU faults; killing on the first matching byte
    /// truncates the diagnostics. The run is killed at whichever is first:
    /// this window, or the `--timeout` deadline. 0 kills on the next poll
    /// after the match.
    #[arg(long, default_value_t = DEFAULT_FAIL_GRACE_SECS)]
    pub fail_grace_secs: u64,

    /// Also copy every run's log, whatever its outcome, to
    /// `<DIR>/<arch>-<cpus>cpu-<run>.log`, ending with a `[run-parallel]`
    /// trailer line that records the run's arch, width, accelerator, outcome,
    /// and host wall time. DIR is created if absent and never purged; a file
    /// of the same name is overwritten.
    #[arg(long, value_name = "DIR")]
    pub save_logs: Option<PathBuf>,

    /// Attach this image as a second disk: its own `virtio-blk-pci` device
    /// (drive `hd1`) beside `disk.img`, presenting the logical block size of
    /// the image's GPT unless `--second-disk-block-size` sets it (an image
    /// with no GPT at 512- or 4096-byte blocks needs it set). `cargo xtask
    /// mkdisk --split-data` authors `disk-data.img` for it.
    #[arg(long, value_name = "PATH")]
    pub second_disk: Option<PathBuf>,

    /// Logical and physical block size, in bytes, of the second disk's
    /// device, overriding the size read from its image (a power of two of at
    /// least 512; a size above the guest driver's 4096 stages the boot whose
    /// second device the driver refuses).
    #[arg(long, value_name = "BYTES", requires = "second_disk")]
    pub second_disk_block_size: Option<u32>,

    /// Place the second disk's device on the first disk's `INTx` line; same
    /// semantics as `cargo xtask run --second-disk-shared-line`.
    #[arg(long, requires = "second_disk")]
    pub second_disk_shared_line: bool,

    /// Attach the debug port, served on `127.0.0.1:<PORT>`; same semantics
    /// as `cargo xtask run --debug-port`. Requires `--parallel 1` (one host
    /// port).
    #[arg(long, value_name = "PORT")]
    pub debug_port: Option<u16>,

    /// Stage the GDB stub for these boots, attached to the process named
    /// NAME; same semantics as `cargo xtask run --debug-target`. Requires
    /// `--debug-port`.
    #[arg(long, value_name = "NAME", requires = "debug_port")]
    pub debug_target: Option<String>,
}

// ── KtestTiming ───────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct KtestTimingArgs
{
    /// ktest boot logs: each is tabulated on its own, or the one log
    /// `--baseline` and `--write-baseline` take.
    pub logs: Vec<PathBuf>,

    /// The narrower-width log of a cross-width comparison (requires `--wide`).
    #[arg(long, requires = "wide", conflicts_with_all = ["baseline", "write_baseline"])]
    pub base: Option<PathBuf>,

    /// The wider-width log of a cross-width comparison (requires `--base`).
    #[arg(long, requires = "base", conflicts_with_all = ["baseline", "write_baseline"])]
    pub wide: Option<PathBuf>,

    /// Compare the one LOG against this baseline file (same arch and width).
    #[arg(long, value_name = "FILE", conflicts_with = "write_baseline")]
    pub baseline: Option<PathBuf>,

    /// Write the one LOG's timing to this baseline file, with the commit and
    /// the host's CPU, kernel, QEMU, and accelerator settings in its header.
    #[arg(long, value_name = "FILE")]
    pub write_baseline: Option<PathBuf>,

    /// The commit the LOG ran at, recorded by `--write-baseline`.
    #[arg(long, default_value = "HEAD", requires = "write_baseline")]
    pub commit: String,

    /// Flag a row whose normalised ratio exceeds this (R/F across widths,
    /// the plain ratio against a baseline).
    #[arg(long, default_value = "1.5")]
    pub threshold: f64,

    /// Flag a row only when its time exceeds the expected time (F times the
    /// base, or the baseline's) by at least this many seconds.
    #[arg(long, default_value = "1.0")]
    pub min_secs: f64,
}

// ── Symbolize ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct SymbolizeArgs
{
    /// The ELF image the addresses fall in (a sysroot binary, or its build
    /// output under `target/`).
    #[arg(long, value_name = "PATH", required_unless_present_any = ["kernel", "log"])]
    pub binary: Option<PathBuf>,

    /// Resolve against the sysroot's kernel image
    /// (`sysroot/esp/EFI/seraph/kernel`).
    #[arg(long, conflicts_with = "binary")]
    pub kernel: bool,

    /// Load bias, in hex: the runtime address of the image's link address 0
    /// (a PIE's `image bias=` or, for init, `init: PIE bias=` log value; the
    /// kernel's `kaslr: slide=` value).
    #[arg(long, value_name = "HEX", default_value = "0", value_parser = parse_hex_arg)]
    pub bias: u64,

    /// Runtime addresses to resolve, in hex (`0x` optional).
    #[arg(
        required_unless_present = "log",
        value_name = "ADDR",
        value_parser = parse_hex_arg
    )]
    pub addresses: Vec<u64>,

    /// A serial log: print every crash-report block in it with its code
    /// addresses resolved, each process's image found in the sysroot by the
    /// log name logd's `reclaim:` line gives its badge, or, for a process
    /// logd names none for, as the one binary whose text span matches.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["binary", "kernel", "bias", "addresses"])]
    pub log: Option<PathBuf>,
}

/// Clap value parser for a hex address.
fn parse_hex_arg(text: &str) -> Result<u64, String>
{
    crate::symbolize::parse_hex(text).map_err(|err| format!("{err:#}"))
}

// ── LintDocs ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct LintDocsArgs {}

// ── CommitCheck ───────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct CommitCheckArgs
{
    /// The commit or ref the range starts after.
    #[arg(long, default_value = "origin/master")]
    pub base: String,

    /// The commit or ref the range ends at.
    #[arg(long, default_value = "HEAD")]
    pub head: String,

    /// Fail on warnings too.
    #[arg(long)]
    pub strict: bool,
}

// ── PrCheck ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct PrCheckArgs
{
    /// The pull request's number.
    pub pr: u64,

    /// Also check the merge gate: every check green, a clean merge state, the
    /// base branch included, and a passing last review record for the head.
    #[arg(long)]
    pub gate: bool,

    /// Fail on warnings too.
    #[arg(long)]
    pub strict: bool,
}

// ── ReviewCheck / ReviewLedger ────────────────────────────────────────────────

#[derive(Parser)]
pub struct ReviewCheckArgs
{
    /// The pull request's number.
    pub pr: u64,
}

#[derive(Parser)]
pub struct ReviewLedgerArgs
{
    /// The pull request's number.
    pub pr: u64,
}

// ── IssueEdit / IssueFile ─────────────────────────────────────────────────────

#[derive(Parser)]
pub struct IssueEditArgs
{
    /// The Issue's number.
    pub issue: u64,

    /// The file holding the new body.
    #[arg(long)]
    pub body_file: PathBuf,

    /// Allow a body with fewer task-list items than the Issue has.
    #[arg(long)]
    pub allow_removal: bool,
}

#[derive(Parser)]
pub struct IssueFileArgs
{
    /// The Issue's title.
    #[arg(long)]
    pub title: String,

    /// The file holding the body.
    #[arg(long)]
    pub body_file: PathBuf,

    /// A label; repeat for each. At least one subsystem and one class label.
    #[arg(long)]
    pub label: Vec<String>,

    /// The milestone's title.
    #[arg(long)]
    pub milestone: Option<String>,

    /// File without a milestone: future-state work no release has scheduled.
    #[arg(long)]
    pub unscheduled: bool,
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn every_built_crate_is_accepted_as_a_build_component()
    {
        let names: Vec<&str> = crate::commands::build::spec_names().collect();
        assert!(names.contains(&"crashme") && names.contains(&"crashd"));
        for name in names
        {
            assert_eq!(parse_build_component(name), Ok(BuildComponent::Spec(name)));
        }
        assert_eq!(parse_build_component("boot"), Ok(BuildComponent::Boot));
        assert_eq!(parse_build_component("all"), Ok(BuildComponent::All));
        assert!(parse_build_component("no-such-crate").is_err());
    }
}
