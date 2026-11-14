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
use crate::context::Profile;
use crate::disk::BlockSize;
use crate::qemu::{DiskLine, Iommu, RiscvMmu, RiscvZkr, X86Paging};

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

    /// Lint the test code, then run Seraph unit tests on the host and, built
    /// for riscv64, under QEMU's user-mode emulator (see xtask/README.md).
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

    /// Check that the log-level configuration reaches the services init
    /// spawns: compose the bundle with vfsd set to debug, boot the current
    /// sysroot once through `run-parallel`, assert that vfsd's and fatfs's
    /// debug lines appear and devmgr's and procmgr's do not, and compose the
    /// bundle back (see xtask/README.md).
    TestLogLevel(TestLogLevelArgs),

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

    /// Capture the ACPI tables of one QEMU configuration into the `shared/aml`
    /// fixtures: boot the firmware alone on a blank disk, save the guest's
    /// memory over QMP once the firmware has installed its tables, find the
    /// RSDP, walk the XSDT, and write the DSDT and every SSDT with a note of
    /// the capture (see xtask/README.md).
    CaptureAcpi(CaptureAcpiArgs),

    /// Check the mechanical documentation and source-header rules: Markdown
    /// column limit, file-header layout, `## Summarized By` shape, forward
    /// links, order, and labels, and document reachability from the root
    /// README. Runs in CI's host-tests job; see xtask/README.md for the rule
    /// list and levels.
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

    /// Build two commits (by default the merge base with `origin/master` and
    /// `HEAD`) for each architecture and profile in one scratch worktree, and
    /// compare every installed image in the parts a loader reads; print each
    /// image and part that differs and a verdict line, and fail when one
    /// differs (see xtask/README.md).
    CompareImages(CompareImagesArgs),

    /// Validate the saved run records of a pull request's pre-merge review
    /// (`target/xtask/review/pr<N>/`) against the record shape (see
    /// xtask/README.md).
    ReviewCheck(ReviewCheckArgs),

    /// Build `ledger.json` from the saved run records of a pull request's
    /// pre-merge review, or print a release review's ledger for the files
    /// named: the findings a later run must not re-raise (see
    /// xtask/README.md).
    ReviewLedger(ReviewLedgerArgs),

    /// Print the scope of a release review as JSON, in pages of bounded
    /// size with a digest each: the range's files, its first-parent units
    /// and their files, and the open Issues (see xtask/README.md).
    ReleaseScope(ReleaseScopeArgs),

    /// Replace a GitHub Issue's body from a file, refusing an empty body or
    /// one that lost task-list items, keeping a backup, and verifying the
    /// edit (see xtask/README.md).
    IssueEdit(IssueEditArgs),

    /// File a GitHub Issue with the labels and milestone docs/conventions.md
    /// requires, and verify that both were applied (see xtask/README.md).
    IssueFile(IssueFileArgs),

    /// Keep the on-disk state of an orchestration batch
    /// (`target/xtask/orchestration/state.json`) and its log: the
    /// orchestrator, the exclusive grant, the workers, the merge order, the
    /// open questions and the rulings in force. `orch state` prints it (see
    /// xtask/README.md).
    Orch(OrchArgs),

    /// Show the shared host's state as the launch rules read it: the load,
    /// the exclusive grant, the commands holding the host, and the QEMUs
    /// running (see xtask/README.md "Host launch rules").
    Host(HostCommandArgs),

    /// Answer a hook of the assistant's harness: read the event's JSON on
    /// stdin and print the answer the harness reads. `.claude/settings.json`
    /// names these commands (see xtask/README.md).
    Hook(HookArgs),
}

impl CliCommand
{
    /// The host launch rules' options of a command the rules admit as a
    /// build (`crate::host_lock::admit_build`), which `main` admits before it
    /// runs the command; `None` for every other command. A command that boots
    /// QEMU is admitted by its own entry point instead, which knows the size
    /// of its boot.
    ///
    /// The match names every command, so a new one states here whether it
    /// compiles on the shared host.
    pub fn build_host(&self) -> Option<&HostArgs>
    {
        match self
        {
            Self::Build(args) => Some(&args.host),
            Self::Clean(args) => Some(&args.host),
            Self::Test(args) => Some(&args.host),
            Self::CompareImages(args) => Some(&args.host),
            Self::Run(_)
            | Self::RunParallel(_)
            | Self::KtestTiming(_)
            | Self::Symbolize(_)
            | Self::Mkdisk(_)
            | Self::ComposeBundle(_)
            | Self::TestTerminal(_)
            | Self::TestVmgenid(_)
            | Self::TestKaslr(_)
            | Self::TestCrashReport(_)
            | Self::TestMapRedo(_)
            | Self::TestLogLevel(_)
            | Self::TestDebugPort(_)
            | Self::TestGdb(_)
            | Self::CaptureAcpi(_)
            | Self::LintDocs(_)
            | Self::CommitCheck(_)
            | Self::PrCheck(_)
            | Self::ReviewCheck(_)
            | Self::ReviewLedger(_)
            | Self::ReleaseScope(_)
            | Self::IssueEdit(_)
            | Self::IssueFile(_)
            | Self::Orch(_)
            | Self::Host(_)
            | Self::Hook(_) => None,
        }
    }
}

// ── Host launch rules ─────────────────────────────────────────────────────────

/// The host launch rules' options every command that loads the host takes
/// (`crate::host_lock`).
#[derive(clap::Args, Clone, Debug, Default)]
pub struct HostArgs
{
    /// When the host refuses this command, wait up to SECS for it to admit
    /// it, asking again every 10 s, instead of failing at once; at the bound
    /// the command fails with the last refusal.
    #[arg(long, value_name = "SECS")]
    pub wait_host: Option<u64>,

    /// Start even when the host's rules refuse, printing the refusal: for
    /// the maintainer's interactive use. A boot still registers, so other
    /// commands see it.
    #[arg(long)]
    pub host_override: bool,
}

/// The host launch rules' options of a command that boots QEMU.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct BootHostArgs
{
    #[command(flatten)]
    pub common: HostArgs,

    /// Run beside no other QEMU, and keep every other boot off the host
    /// while it runs: the re-run of a boot whose timeout or timing failure
    /// came beside another QEMU, before that failure counts.
    #[arg(long, conflicts_with = "timing")]
    pub alone: bool,

    /// A timing-sensitive measurement: run beside no other QEMU, under the
    /// large-boot load limit, and refuse builds while it runs.
    #[arg(long)]
    pub timing: bool,

    /// Boot under the exclusive grant `cargo xtask orch grant set` gave
    /// HOLDER. While a grant is outstanding, a boot that does not name its
    /// holder is refused.
    #[arg(long, value_name = "HOLDER")]
    pub grant: Option<String>,
}

#[derive(Parser)]
pub struct HostCommandArgs
{
    #[command(subcommand)]
    pub command: HostCommand,
}

#[derive(Subcommand)]
pub enum HostCommand
{
    /// Print the host's state: the 1-minute load and its limits, the
    /// exclusive grant, the live holders, and the QEMUs running.
    Status,
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

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: HostArgs,
}

impl BuildArgs
{
    /// The build profile `--release` selects.
    pub fn profile(&self) -> Profile
    {
        if self.release
        {
            Profile::Release
        }
        else
        {
            Profile::Debug
        }
    }
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

#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line switch (`--gdb`, `--headless`, `--verbose`, \
              `--second-disk-shared-line`, `--test-devices`) that clap maps one-to-one; they are \
              not states of one machine"
)]
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

    /// Whether the guest RISC-V CPU implements the Zkr entropy source
    /// (riscv64 only; ignored on `x86_64`). `off` boots the kernel's
    /// hardware-RNG path without a source: its probe of the `seed` CSR traps
    /// and the pool seeds from the firmware boot seed and jitter.
    #[arg(long, default_value = "on")]
    pub riscv_zkr: RiscvZkr,

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
    /// the same line), and launch both disks with no MSI-X, staging the boot
    /// in which two virtio-blk devices share one line.
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

    /// Attach the test devices svctest's devmgr phases drive through the
    /// test-only drivers: QEMU's `edu` device and four `pci-testdev`
    /// functions. A svctest boot needs them (docs/testing.md § Gating).
    #[arg(long)]
    pub test_devices: bool,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

impl RunArgs
{
    /// The second disk's `INTx` line `--second-disk-shared-line` selects.
    pub fn second_disk_line(&self) -> DiskLine
    {
        if self.second_disk_shared_line
        {
            DiskLine::Shared
        }
        else
        {
            DiskLine::Own
        }
    }
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
    /// and only the ESP, root and swap partitions on `disk.img`; boot the pair
    /// with `--second-disk disk-data.img`. Without it `disk.img` carries all
    /// four and a `disk-data.img` an earlier authoring left is removed.
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

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
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

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
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

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
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

    /// Attach the test devices, as `run --test-devices` does: a staged
    /// svctest needs them to reach its pass marker.
    #[arg(long)]
    pub test_devices: bool,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

// ── TestLogLevel ──────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestLogLevelArgs
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

    /// Attach the test devices, as `run --test-devices` does: a staged
    /// svctest needs them to reach its pass marker.
    #[arg(long)]
    pub test_devices: bool,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

// ── TestDebugPort ─────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestDebugPortArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// The host TCP port the debug port is served on; without it, a port
    /// free on `127.0.0.1` when the boot starts.
    #[arg(long)]
    pub port: Option<u16>,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

// ── TestGdb ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestGdbArgs
{
    /// Target architecture.
    #[arg(long, default_value = "x86_64")]
    pub arch: Arch,

    /// The host TCP port the debug port is served on; without it, a port
    /// free on `127.0.0.1` when the boot starts.
    #[arg(long)]
    pub port: Option<u16>,

    /// The host GDB to run (it must debug the architecture).
    #[arg(long, default_value = "gdb")]
    pub gdb: String,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,

    /// Guest memory size in MiB (QEMU -m).
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

// ── CaptureAcpi ──────────────────────────────────────────────────────────────

/// A QEMU configuration whose ACPI tables `capture-acpi` captures; each is
/// the tree's launch (`crate::qemu::build_qemu_argv`) of one architecture
/// with the test devices attached, plus the devices it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AcpiConfig
{
    /// q35 as the tree boots it.
    X86Default,
    /// q35 with an empty PCI Express root port
    /// (`pcie-root-port,id=rp0,chassis=1,addr=0x1c`).
    X86Rootport,
    /// `x86-rootport` with ACPI PCI hotplug off
    /// (`-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off`), so the
    /// firmware grants native hotplug.
    X86RootportNative,
    /// riscv64 `virt` with an empty PCI Express root port
    /// (`pcie-root-port,id=rp0,chassis=1`).
    Riscv64Rootport,
}

#[derive(Parser)]
pub struct CaptureAcpiArgs
{
    /// The configuration to capture.
    #[arg(long)]
    pub config: AcpiConfig,

    /// The directory the tables are written to (default:
    /// `shared/aml/fixtures/<config>`). Its `.aml` files are replaced.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Seconds to wait for the firmware to reach its boot options.
    #[arg(long, default_value = "600")]
    pub timeout: u64,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
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

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: HostArgs,
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct TestArgs
{
    /// Test a single component (default: all).
    #[arg(long, default_value = "all")]
    pub component: TestComponent,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: HostArgs,
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

#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line switch (`--debug-listen`, `--hold-on-hang`, \
              `--second-disk-shared-line`, `--test-devices`) that clap maps one-to-one; they are \
              not states of one machine"
)]
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

    /// Whether the guest RISC-V CPU implements the Zkr entropy source
    /// (riscv64 only; ignored on `x86_64`), for every run in the batch. `off`
    /// boots the kernel's hardware-RNG path without a source: its probe of the
    /// `seed` CSR traps and the pool seeds from the firmware boot seed and
    /// jitter.
    #[arg(long, default_value = "on")]
    pub riscv_zkr: RiscvZkr,

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

    /// Attach the test devices; same semantics as `cargo xtask run
    /// --test-devices`.
    #[arg(long)]
    pub test_devices: bool,

    /// The shared host's launch rules (see xtask/README.md "Host launch
    /// rules").
    #[command(flatten)]
    pub host: BootHostArgs,
}

impl RunParallelArgs
{
    /// The second disk's `INTx` line `--second-disk-shared-line` selects.
    pub fn second_disk_line(&self) -> DiskLine
    {
        if self.second_disk_shared_line
        {
            DiskLine::Shared
        }
        else
        {
            DiskLine::Own
        }
    }
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
pub struct LintDocsArgs;

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

// ── CompareImages ─────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct CompareImagesArgs
{
    /// The base commit (default: the merge base of the head with
    /// `origin/master`, the base of the PR's own diff).
    #[arg(long)]
    pub base: Option<String>,

    /// The head commit.
    #[arg(long, default_value = "HEAD")]
    pub head: String,

    /// The architectures to build (default: both). Repeatable, or
    /// comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub arch: Vec<Arch>,

    /// The profiles to build (default: both). Repeatable, or
    /// comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub profile: Vec<Profile>,

    /// The shared host's launch rules; `--wait-host` is passed on to each
    /// build.
    #[command(flatten)]
    pub host: HostArgs,
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
    /// The pull request's number: write `ledger.json` beside its records.
    #[arg(conflicts_with = "release")]
    pub pr: Option<u64>,

    /// The target version `X.Y.Z` of a release review: print its ledger, the
    /// entries of the range's pull requests and of the release's own runs.
    #[arg(long, requires = "from")]
    pub release: Option<String>,

    /// The previous release tag, where the release's range starts.
    #[arg(long, requires = "release")]
    pub from: Option<String>,

    /// With `--release`, print only the entries for this file; repeatable.
    #[arg(long, requires = "release")]
    pub file: Vec<String>,
}

// ── ReleaseScope ──────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct ReleaseScopeArgs
{
    /// The previous release tag (or any commit) the range starts at.
    #[arg(long)]
    pub from: String,

    /// The candidate head the range ends at.
    #[arg(long, default_value = "HEAD")]
    pub head: String,

    /// The most entries one page holds: a range file, an open Issue, or a
    /// file of a unit (a unit with no file counts one).
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u64).range(1..))]
    pub page_entries: u64,

    /// Print page `<list>:<n>` (1-based) of `files`, `units`, or `issues`
    /// instead of the summary.
    #[arg(long, value_name = "LIST:N")]
    pub page: Option<String>,
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

    /// Allow a body that drops, rewords, or reopens the Issue's task-list
    /// items.
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

    /// File without a milestone: work that cannot be done now. Needs
    /// `--reason`.
    #[arg(long)]
    pub unscheduled: bool,

    /// Why an `--unscheduled` Issue cannot be done now; its body states the
    /// same reason in a `No milestone: <reason>` line.
    #[arg(long, value_enum)]
    pub reason: Option<UnscheduledReason>,
}

/// Why an Issue may stay without a milestone (docs/conventions.md
/// § Milestones).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum UnscheduledReason
{
    /// It needs hardware the project does not have.
    Hardware,
    /// It is not possible yet.
    NotPossible,
    /// Whether it belongs in the project is itself undecided.
    Undecided,
}

// ── Orch ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct OrchArgs
{
    #[command(subcommand)]
    pub command: OrchCommand,
}

#[derive(Subcommand)]
pub enum OrchCommand
{
    /// Start a batch: a fresh state and the first line of its log. Refuses
    /// while a batch's state exists.
    Start
    {
        /// The batch's goal, in one line.
        #[arg(long)]
        goal: String,
    },

    /// Print the state as text, or as the stored JSON with `--json`.
    State
    {
        /// Print the stored JSON instead of the text form.
        #[arg(long)]
        json: bool,
    },

    /// Append one timestamped line to the batch's log.
    Log
    {
        /// The line; several words are joined with spaces.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        line: Vec<String>,
    },

    /// Record the current orchestrator's agent id, or print it when none is
    /// given.
    Orchestrator
    {
        /// The agent id workers report to.
        id: Option<String>,
    },

    /// Set fields of a worker, creating it when it is new, or remove it.
    Worker(OrchWorkerArgs),

    /// Record the exclusive grant and the requests queued for it.
    Grant
    {
        #[command(subcommand)]
        command: OrchGrantCommand,
    },

    /// Replace the merge order.
    Order
    {
        /// The PRs in the order they merge; none clears the order.
        items: Vec<String>,
    },

    /// Record a question the maintainer has open, or close one.
    Question
    {
        #[command(subcommand)]
        command: OrchQuestionCommand,
    },

    /// Record a ruling in force for the batch, or drop one.
    Ruling
    {
        #[command(subcommand)]
        command: OrchRulingCommand,
    },

    /// End the batch: keep its state beside the log and clear the way for
    /// the next `orch start`.
    End,
}

#[derive(Parser)]
pub struct OrchWorkerArgs
{
    /// The worker's name in the batch (for example `W3`).
    pub name: String,

    /// Remove the worker from the state.
    #[arg(long, conflicts_with_all = ["id", "model", "effort", "scope", "branch", "worktree", "pr", "phase", "status"])]
    pub remove: bool,

    /// The worker's agent id.
    #[arg(long)]
    pub id: Option<String>,

    /// The model the worker runs on.
    #[arg(long)]
    pub model: Option<String>,

    /// The worker's effort level.
    #[arg(long)]
    pub effort: Option<String>,

    /// The commit-title scope of its PR.
    #[arg(long)]
    pub scope: Option<String>,

    /// Its branch.
    #[arg(long)]
    pub branch: Option<String>,

    /// The path of its worktree.
    #[arg(long)]
    pub worktree: Option<String>,

    /// Its PR's number.
    #[arg(long)]
    pub pr: Option<String>,

    /// Its phase: planning, coding, review, gate, merged, retired, or dead.
    #[arg(long)]
    pub phase: Option<String>,

    /// Its last report, in one line.
    #[arg(long)]
    pub status: Option<String>,
}

#[derive(Subcommand)]
pub enum OrchGrantCommand
{
    /// Give the exclusive grant. Refuses while one is outstanding.
    Set
    {
        /// The worker that holds the grant.
        holder: String,
        /// The commands the grant covers, flags included.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        commands: Vec<String>,
    },
    /// End the outstanding grant.
    Clear,
    /// Queue a request for the grant.
    Queue
    {
        /// The worker that asks.
        holder: String,
        /// The commands it asks for, flags included.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        commands: Vec<String>,
    },
    /// Drop a queued request.
    Unqueue
    {
        /// The worker whose request is dropped.
        holder: String,
    },
}

#[derive(Subcommand)]
pub enum OrchQuestionCommand
{
    /// Record an open question.
    Add
    {
        /// The file that holds its detail; give it before the id.
        #[arg(long)]
        file: Option<String>,
        /// A short id to close it by.
        id: String,
        /// The question, in one line.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    /// Close a question once it is answered and the answer recorded.
    Close
    {
        /// The id it was added under.
        id: String,
    },
}

#[derive(Subcommand)]
pub enum OrchRulingCommand
{
    /// Record a ruling in force for the batch.
    Add
    {
        /// The ruling, stated as a decision in one line.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    /// Drop a ruling by the number `orch state` prints.
    Drop
    {
        /// The ruling's number.
        number: usize,
    },
}

// ── Hook ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct HookArgs
{
    #[command(subcommand)]
    pub event: HookEvent,
}

#[derive(Subcommand)]
pub enum HookEvent
{
    /// `PreToolUse` of the Bash tool: refuse a direct cargo build, a merge
    /// or an Issue filing by a subagent that is not the orchestrator, and a
    /// merge that fails the merge gate.
    Bash,

    /// `SubagentStop` of a worker: refuse a hand-back from a worktree on a
    /// detached HEAD or one that does not differ from `origin/master`.
    SubagentStop,

    /// `SessionStart` after a session's compaction: name what to read again.
    CompactStart,

    /// `PreCompact`: print the instructions for the compaction summary.
    PreCompact,
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
        parse_build_component("no-such-crate").unwrap_err();
    }

    /// The host options `main` admits a parsed command line with as a build.
    fn build_host_of(argv: &[&str]) -> Option<HostArgs>
    {
        let cli = Cli::try_parse_from(argv).unwrap();
        cli.command.build_host().cloned()
    }

    #[test]
    fn each_command_that_compiles_is_admitted_as_a_build_with_its_host_options()
    {
        for command in ["build", "clean", "test", "compare-images"]
        {
            let host = build_host_of(&["xtask", command, "--wait-host", "30"])
                .unwrap_or_else(|| panic!("`{command}` is not admitted as a build"));
            assert_eq!(host.wait_host, Some(30), "{command}");
            assert!(!host.host_override, "{command}");
        }
        let overridden = build_host_of(&["xtask", "test", "--host-override"]).unwrap();
        assert!(overridden.host_override);
    }

    #[test]
    fn a_boot_or_a_command_that_compiles_nothing_is_not_admitted_as_a_build()
    {
        assert!(build_host_of(&["xtask", "run"]).is_none());
        assert!(build_host_of(&["xtask", "lint-docs"]).is_none());
        assert!(build_host_of(&["xtask", "host", "status"]).is_none());
    }
}
