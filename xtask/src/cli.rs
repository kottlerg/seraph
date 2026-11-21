// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/cli.rs

//! The xtask command table: every command, its arguments and its help,
//! declared with the `crate::argparse` macros, which parse it as clap 4 did.
//!
//! Add a new top-level command by adding a variant to `CliCommand` and a
//! corresponding `args!` struct below, then handle it in `main.rs`.

use std::path::PathBuf;

use crate::argparse::{Command, Leaf, args, plain_field, subcommands, value_enum};

use crate::arch::Arch;
use crate::bundle::Harness;
use crate::context::Profile;
use crate::disk::BlockSize;
use crate::esp::Knob;
use crate::qemu::{DiskLine, Iommu, QemuDisplay, RiscvMmu, RiscvZkr, X86Paging, X86ShadowStack};

args! {
    /// Top-level CLI entry point.
    pub struct Cli
    {
        #[command(subcommand)]
        pub command: CliCommand,
    }
}

impl Cli
{
    /// The command table.
    #[must_use]
    pub fn command() -> Command
    {
        Command::root::<Self>(
            "xtask",
            "Seraph build task runner — invoke via `cargo xtask`",
        )
    }

    /// Parse the process's command line. Help is printed to stdout with exit
    /// status 0; a usage error, or the help of a command given no subcommand,
    /// to stderr with exit status 2.
    #[must_use]
    pub fn parse() -> Self
    {
        let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
        Self::command()
            .parse_os_into(&argv)
            .unwrap_or_else(|err| err.exit())
    }
}

subcommands! {
    /// Available subcommands.
    pub enum CliCommand
    {
        /// Build Seraph components and populate the sysroot.
        Build(BuildArgs),

        /// Boot Seraph under QEMU against the populated sysroot (run
        /// `cargo xtask build` first): one interactive boot, or with `--runs N`
        /// N unattended boots, each classified by its log.
        Run(RunArgs),

        /// Remove the sysroot, the symbols store and the disk images (and with
        /// `--all` cargo's target/).
        Clean(CleanArgs),

        /// Run Seraph's tests: without a case, check formatting and lint the test
        /// code, then run the unit tests on the host and, built for riscv64,
        /// under QEMU's user-mode emulator; with a CASE, boot the current
        /// sysroot for that host-driven QEMU case; with `--cell`, run every
        /// case a CI validate cell runs (see xtask/README.md).
        Test(TestArgs),

        /// Regenerate the reference vectors of shared/crypto/testkit with
        /// OpenSSL, or with `--check` fail unless they regenerate identically.
        CryptoVectors(CryptoVectorsArgs),

        /// Read preserved ktest boot logs (from `run --runs N --save-logs`) and
        /// print per-tier and per-cell wall times; with `--base` and `--wide`,
        /// compare two widths against their width factor; with `--baseline`,
        /// compare one log against a checked-in baseline of the same width; with
        /// `--write-baseline`, write one. Report-only: a flagged row never fails
        /// the command. See xtask/README.md for the tables and the baseline format.
        KtestTiming(KtestTimingArgs),

        /// Resolve runtime addresses in a loaded ELF image (a binary, or the
        /// sysroot's kernel) to function, file, and line from its DWARF, or to the
        /// nearest function symbol when no DWARF covers an address; a stripped
        /// image's symbols are the symbols store's file of its build id. Each
        /// output line names the source it used. With `--log`, print every
        /// crash-report block of a serial log with its addresses resolved against
        /// the sysroot's binaries. See xtask/README.md.
        Symbolize(SymbolizeArgs),

        /// Mirror `rootfs/` into the sysroot, re-synthesise test fixtures,
        /// choose the harness, the bootloader knobs and the log-level
        /// configuration the image boots, and regenerate `disk.img` without
        /// invoking cargo. The mirror is authoritative over `config/`+`data/`
        /// (deletions in `rootfs/` are pruned); use `--repack-only` to pack a
        /// hand-staged sysroot without it (the repository's data files, the
        /// log-level configuration among them, are installed either way; pack
        /// another configuration with `--log-levels`). Every pack re-signs
        /// the sysroot's signed objects in place, then checks the images it
        /// wrote with `fsck.fat -n` (dosfstools) and reads their ESP back
        /// against the root partition. Requires an arch-tagged sysroot from a
        /// prior `cargo xtask build`.
        Mkdisk(MkdiskArgs),

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
        /// (`target/xtask/review/pr<N>/`) against the record shape and build
        /// `ledger.json` from them, or print a release review's ledger for the
        /// files named: the findings a later run must not re-raise (see
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
            Self::Test(args) => args.unit_tests().then_some(&args.host.common),
            Self::CryptoVectors(args) => Some(&args.host),
            Self::CompareImages(args) => Some(&args.host),
            Self::Run(_)
            | Self::KtestTiming(_)
            | Self::Symbolize(_)
            | Self::Mkdisk(_)
            | Self::CaptureAcpi(_)
            | Self::LintDocs(_)
            | Self::CommitCheck(_)
            | Self::PrCheck(_)
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

args! {
    /// The host launch rules' options every command that loads the host takes
    /// (`crate::host_lock`).
    #[derive(Clone, Debug, Default)]
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
}

args! {
    /// The host launch rules' options of a command that boots QEMU.
    #[derive(Clone, Debug, Default)]
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
        /// load limit of 10 of a boot that needs the host to itself, and refuse
        /// builds while it runs.
        #[arg(long)]
        pub timing: bool,

        /// Boot under the exclusive grant `cargo xtask orch grant set` gave
        /// HOLDER. While a grant is outstanding, a boot that does not name its
        /// holder is refused.
        #[arg(long, value_name = "HOLDER")]
        pub grant: Option<String>,
    }
}

args! {
    pub struct HostCommandArgs
    {
        #[command(subcommand)]
        pub command: HostCommand,
    }
}

subcommands! {
    pub enum HostCommand
    {
        /// Print the host's state: the 1-minute load and its limits, the
        /// exclusive grant, the live holders, and the QEMUs running.
        Status,
    }
}

// ── Build ─────────────────────────────────────────────────────────────────────

args! {
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

        /// Skip the formatting check (`cargo fmt --check`) and the
        /// per-component `cargo check` (clippy), which would otherwise double
        /// the cargo invocations per component. `cargo xtask compare-images`
        /// and `cargo xtask test signing` and `rollback` set it for the builds
        /// they run.
        /// Use `cargo xtask build` without it for the full lint pass.
        #[arg(long, hide = true)]
        pub skip_lints: bool,

        /// The shared host's launch rules (see xtask/README.md "Host launch
        /// rules").
        #[command(flatten)]
        pub host: HostArgs,
    }
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

impl Leaf for BuildComponent
{
    fn parse(text: &str) -> Result<Self, String>
    {
        parse_build_component(text)
    }
}

plain_field!(BuildComponent);

/// The value parser of a [`BuildComponent`]: `boot`, `all`, or the crate
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

args! {
    /// The launch configuration of a boot of the sysroot: the machine QEMU
    /// presents and what is attached to it, the same in both of `run`'s modes.
    #[derive(Clone, Debug)]
    pub struct LaunchArgs
    {
        /// Target architecture.
        #[arg(long, default_value = "x86_64")]
        pub arch: Arch,

        /// Number of vCPUs to expose to the guest (QEMU -smp).
        #[arg(long, default_value = "4")]
        pub cpus: u32,

        /// Logical CPUs per core in the guest's topology (QEMU
        /// `-smp <cpus>,threads=<n>`); must divide `--cpus`. 2 presents SMT
        /// sibling pairs, which the kernel's placement spreads threads across
        /// (core/kernel/docs/scheduler.md "SMT Awareness"); riscv64 takes each
        /// hart as a core of its own whatever this says.
        #[arg(long, default_value = "1")]
        pub threads_per_core: u32,

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

        /// Whether the guest x86-64 CPU offers CET supervisor shadow stacks
        /// (`x86_64` only; ignored on riscv64). Pins the QEMU CPU's `cet-ss`
        /// property, so the host's CPU never decides it; a QEMU without the
        /// property cannot offer them and gets no pin. `on` boots the kernel on
        /// shadow stacks, or refuses to boot when the accelerator or the QEMU
        /// cannot offer them; the cet cell (`cargo xtask test cet`) is where they
        /// are tested.
        #[arg(long, default_value = "off")]
        pub x86_shadow_stack: X86ShadowStack,

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

        /// Attach the debug port: a `virtio-serial-pci` device with one
        /// `virtconsole` port, which devmgr binds as the debug port, its host end a TCP server QEMU listens with on
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
        /// test-only drivers: QEMU's `edu` device and five `pci-testdev`
        /// functions. A svctest boot needs them (docs/testing.md § Gating).
        #[arg(long)]
        pub test_devices: bool,
    }
}

impl LaunchArgs
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

args! {
    pub struct RunArgs
    {
        #[command(flatten)]
        pub launch: LaunchArgs,

        /// Boot N times unattended and classify each run's log as PASS, FAIL,
        /// HANG, OK, ERR or QEMU-CRASH by the `--pass` and `--fail` patterns,
        /// failing unless every run passes (a QEMU-CRASH is tolerated). Without
        /// it, `run` is one interactive boot whose serial output is the
        /// terminal's.
        #[arg(long, value_name = "N")]
        pub runs: Option<u32>,

        /// What the guest presents for display. `window` attaches QEMU std VGA
        /// and shows it in a window; `framebuffer` attaches it with no window
        /// (`-display none`), so the framebuffer driver runs on a host without a
        /// graphical backend: the framebuffer device cell of the local and
        /// release host runs (docs/testing.md "Coverage tiers"); `headless`
        /// attaches no adapter, so the bootloader finds no GOP and devmgr
        /// spawns no framebuffer driver. Default: `window` for the interactive
        /// boot, `headless` with `--runs`, which refuses `window`.
        #[arg(long)]
        pub display: Option<QemuDisplay>,

        /// Start QEMU with a GDB server on localhost:1234, paused at startup
        /// (QEMU `-s -S`). Interactive boot only.
        #[arg(long, conflicts_with_all = ["runs", "debug_listen"])]
        pub gdb: bool,

        /// Expose the guest's gdbstub on localhost:1234 without pausing it
        /// (QEMU `-s`), so a wedged guest can be attached to post hoc:
        /// `gdb -ex 'target remote :1234'`. With `--runs`, requires
        /// `--parallel 1` (one gdbstub port).
        #[arg(long)]
        pub debug_listen: bool,

        /// Show all serial output including pre-boot firmware noise
        /// (suppressed by default). Interactive boot only.
        ///
        /// By default, output is suppressed until the first line containing
        /// '[--------] boot:', hiding UEFI/OpenSBI debug spam. The
        /// control-sequence filter (drops xterm window manipulation,
        /// alternate-screen toggles, mouse tracking, etc.) is always on in
        /// both modes — verbose only disables the marker gate, not the
        /// filter.
        #[arg(long, conflicts_with = "runs")]
        pub verbose: bool,

        /// Concurrency of `--runs`: number of QEMU instances in flight at once;
        /// the runs are dispatched in waves of this many.
        #[arg(long, default_value = "1", requires = "runs")]
        pub parallel: u32,

        /// Per-run timeout of `--runs`, in seconds. A run still alive at this
        /// point is killed and classified as HANG.
        #[arg(long, default_value = "30", requires = "runs")]
        pub timeout: u64,

        /// Regex marking a successful run of `--runs`. On match (and every
        /// `--require` and `--crash-reports` check holding) the log is
        /// discarded and the run is classified PASS. The default matches the
        /// cross-harness terminal marker `[<harness>] ALL TESTS PASSED`
        /// standardised in [`docs/testing.md`](../../docs/testing.md); override
        /// for other rootfs configurations.
        #[arg(long, default_value = DEFAULT_PASS_REGEX, requires = "runs")]
        pub pass: String,

        /// Regex marking a failed run of `--runs`. On match the log is
        /// preserved as FAIL-<run>.log. Failure takes precedence over success.
        /// The default matches the cross-harness terminal marker
        /// `[<harness>] SOME TESTS FAILED`
        /// ([`docs/testing.md`](../../docs/testing.md)) plus the kernel's
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
        #[arg(long, default_value = DEFAULT_FAIL_REGEX, requires = "runs")]
        pub fail: String,

        /// A further regex marking a failed run of `--runs`, matched beside
        /// `--fail` rather than in its place, so the default's death markers
        /// still apply: a run whose log matches either is FAIL, with the same
        /// precedence and `--fail-grace-secs` kill. The framebuffer device cell
        /// passes `'framebuffer case skipped'`, the line svctest logs when no
        /// framebuffer driver runs.
        #[arg(long, value_name = "REGEX", requires = "runs")]
        pub fail_also: Option<String>,

        /// A regex a line of the log must match for a run of `--runs` to pass;
        /// repeatable, each must match. A run whose `--pass` pattern matched
        /// but whose log has no line matching one of these is FAIL, naming the
        /// pattern.
        #[arg(long, value_name = "REGEX", requires = "runs")]
        pub require: Vec<String>,

        /// Check the crash service's report blocks in each passing run's log:
        /// every block well-formed, and `reports` the `crashme` fixture's three
        /// reports, `none` no block at all. A run whose check fails is FAIL; a
        /// QEMU-CRASH run is not checked.
        #[arg(long, requires = "runs")]
        pub crash_reports: Option<CrashReportExpect>,

        /// On a hard-timeout HANG of `--runs`, do not kill the QEMU instance:
        /// print the attach instructions and block until it is terminated
        /// externally, preserving the wedged guest for inspection (pair with
        /// `--debug-listen`). Requires `--parallel 1`.
        #[arg(long, requires = "runs")]
        pub hold_on_hang: bool,

        /// Grace window of `--runs`, in seconds, after the first `--fail`
        /// match before the run is `SIGKILLed`. A kernel fault dump is
        /// multi-line and may be followed by secondary-CPU faults; killing on
        /// the first matching byte truncates the diagnostics. The run is killed
        /// at whichever is first: this window, or the `--timeout` deadline. 0
        /// kills on the next poll after the match.
        #[arg(long, default_value_t = DEFAULT_FAIL_GRACE_SECS, requires = "runs")]
        pub fail_grace_secs: u64,

        /// Also copy every run's log of `--runs`, whatever its outcome, to
        /// `<DIR>/<arch>-<cpus>cpu-<run>.log`, ending with a `[run]` trailer
        /// line that records the run's arch, width, accelerator, outcome, and
        /// host wall time. DIR is created if absent and never purged; a file of
        /// the same name is overwritten.
        #[arg(long, value_name = "DIR", requires = "runs")]
        pub save_logs: Option<PathBuf>,

        /// The shared host's launch rules (see xtask/README.md "Host launch
        /// rules").
        #[command(flatten)]
        pub host: BootHostArgs,
    }
}

// ── Run classification ──────────────────────────────────────────────────────

/// Default `run --fail` regex. Matches the cross-harness
/// `SOME TESTS FAILED` marker plus the kernel's death markers so a crash is
/// classified FAIL rather than HANG. `KERNEL EXCEPTION` + `FATAL:` cover the
/// hardware-trap path; `PANIC( at |: )` covers the Rust `#[panic_handler]`;
/// `entropy: SELFTEST FAIL` covers the kernel entropy self-test.
/// The benign `USERSPACE FAULT` path matches none of these.
pub const DEFAULT_FAIL_REGEX: &str =
    r"SOME TESTS FAILED|KERNEL EXCEPTION|FATAL:|PANIC( at |: )|=== WATCHDOG|entropy: SELFTEST FAIL";

/// Default `run --pass` regex: the cross-harness terminal pass
/// marker `[<harness>] ALL TESTS PASSED` (docs/testing.md § Reporting marker).
pub const DEFAULT_PASS_REGEX: &str = "ALL TESTS PASSED";

/// Default `run --fail-grace-secs`.
pub const DEFAULT_FAIL_GRACE_SECS: u64 = 10;

value_enum! {
    /// What `run --crash-reports` expects of each passing run's log
    /// (`crate::crash_check`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CrashReportExpect
    {
        /// The `crashme` fixture's `vm` and `exception` reports of its main
        /// thread and its `worker` report of a spawned thread: a usertest boot
        /// with crashd staged.
        Reports,
        /// No report block: a boot of an image that stages no crashd.
        None,
    }
}

// ── Mkdisk ────────────────────────────────────────────────────────────────────

args! {
    pub struct MkdiskArgs
    {
        /// Target architecture — must match the existing sysroot's arch tag.
        #[arg(long, default_value = "x86_64")]
        pub arch: Arch,

        /// Repack `disk.img` from the sysroot as it stands, skipping the
        /// `rootfs/` re-mirror; the repository's data files are still
        /// installed, and the sysroot's signed objects re-signed in place, as
        /// every pack signs them. Use after editing the
        /// staged sysroot directly (e.g. adding a test recipe or removing a
        /// default one): a normal re-mirror is authoritative and would restore
        /// `rootfs/`-present recipes and prune `rootfs/`-absent ones, undoing
        /// the manual staging.
        #[arg(long)]
        pub repack_only: bool,

        /// Record the harness whose bundle this and every later pack composes
        /// from the installed files its bundle list names: `init` for the
        /// userspace init, `ktest` for the kernel-test harness. Omit to keep
        /// the recorded harness (`init` after `cargo xtask build`).
        #[arg(long)]
        pub harness: Option<Harness>,

        /// Stage a bootloader knob in `\EFI\seraph\`: `nokaslr` boots the
        /// kernel at its deterministic (un-randomized) layout, for GDB and
        /// symbolization; `mapredo` makes the bootloader redo the first
        /// attempt of its steps 6 and 7. Repeatable, or comma-separated. The
        /// image carries exactly the knobs named: every other is removed.
        #[arg(long, value_delimiter = ',')]
        pub knob: Vec<Knob>,

        /// Install FILE as the log-level configuration init reads
        /// (`/config/init/log-levels.conf`) in place of the repository's
        /// `services/init/log-levels.conf`, which mkdisk installs without it.
        /// Refused unless init's parser accepts every line.
        #[arg(long, value_name = "FILE")]
        pub log_levels: Option<PathBuf>,

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
}

// ── CaptureAcpi ──────────────────────────────────────────────────────────────

value_enum! {
    /// A QEMU configuration whose ACPI tables `capture-acpi` captures; each is
    /// the tree's launch (`crate::qemu::build_qemu_argv`) of one architecture
    /// with the test devices attached, plus the devices it names.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

args! {
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
}

// ── Clean ─────────────────────────────────────────────────────────────────────

args! {
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
}

// ── CryptoVectors ─────────────────────────────────────────────────────────────

args! {
    pub struct CryptoVectorsArgs
    {
        /// Regenerate in memory and fail unless the checked-in files are
        /// byte-identical, writing nothing.
        #[arg(long)]
        pub check: bool,

        /// The shared host's launch rules (see xtask/README.md "Host launch
        /// rules").
        #[command(flatten)]
        pub host: HostArgs,
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

args! {
    pub struct TestArgs
    {
        /// The host-driven QEMU case to run against the populated sysroot (see
        /// xtask/README.md for each). Without a case or `--cell`, `test`
        /// checks formatting, lints the test code and runs the unit tests.
        #[arg(value_name = "CASE", conflicts_with = "cell")]
        pub case: Option<TestCase>,

        /// Run every case the CI validate cell of TESTER runs on `--arch`, in
        /// the registry's order, each whatever another's outcome, and fail when
        /// one failed.
        #[arg(long, value_name = "TESTER")]
        pub cell: Option<Tester>,

        /// The unit tests' component. Unit tests only.
        #[arg(long, default_value = "all", conflicts_with_all = ["case", "cell"])]
        pub component: TestComponent,

        /// Target architecture of a case or a cell (default: `x86_64`).
        #[arg(long)]
        pub arch: Option<Arch>,

        /// Number of vCPUs a case's boots expose to the guest (QEMU -smp;
        /// default: 4).
        #[arg(long)]
        pub cpus: Option<u32>,

        /// Guest memory size in MiB of a case's boots (QEMU -m; default: 512).
        #[arg(long)]
        pub mem: Option<u32>,

        /// The `shutdown` case's causes, one boot each (default: every cause
        /// the architecture has). Repeatable, or comma-separated.
        #[arg(long, value_delimiter = ',', requires = "case")]
        pub cause: Vec<ShutdownCause>,

        /// The `debug-port` case's host TCP port for the debug port; without
        /// it, a port free on `127.0.0.1` when each boot starts.
        #[arg(long, requires = "case")]
        pub port: Option<u16>,

        /// The host GDB the `debug-port` case runs, which must debug the
        /// architecture (default: `gdb`).
        #[arg(long, requires = "case")]
        pub gdb: Option<String>,

        /// Build the bootloader the `signing` case revokes under, or the
        /// `rollback` case raises the floor with, in release mode, as the
        /// sysroot's was built (default: debug).
        #[arg(long)]
        pub release: bool,

        /// The `kaslr` case's riscv64 paging-mode ceiling (default: sv48;
        /// ignored on `x86_64`).
        #[arg(long, requires = "case")]
        pub riscv_mmu: Option<RiscvMmu>,

        /// The `kaslr` case's guest x86-64 paging depth (default: 4; ignored
        /// on riscv64).
        #[arg(long, requires = "case")]
        pub x86_paging: Option<X86Paging>,

        /// The shared host's launch rules (see xtask/README.md "Host launch
        /// rules"). A case admits each of its boots; the unit tests are
        /// admitted as a build.
        #[command(flatten)]
        pub host: BootHostArgs,
    }
}

impl TestArgs
{
    /// Whether the command line runs the unit tests: neither a case nor a
    /// cell. `main` admits that form as a build; a case admits its own boots.
    #[must_use]
    pub fn unit_tests(&self) -> bool
    {
        self.case.is_none() && self.cell.is_none()
    }
}

value_enum! {
    /// Components that can be tested individually.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TestComponent
    {
        Boot,
        Protocol,
        Kernel,
        Init,
        All,
    }
}

value_enum! {
    /// A host-driven QEMU case: one or more boots of the current sysroot that
    /// the host drives or watches, which no in-guest harness can check alone.
    /// The registry (`crate::commands::test::cases`) states each one's
    /// architectures, bundle, boots and cell.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TestCase
    {
        /// Keyboard and serial input through the terminal, and keyboard input
        /// again after a restart of the input driver.
        Terminal,
        /// The kernel's randomized layout differs between boots, and the
        /// `nokaslr` knob gives the deterministic one.
        Kaslr,
        /// Each signature verifier refuses a tampered kernel, a tampered bundle
        /// entry, a revoked key, and tampered, wrong-role and foreign-signed
        /// rootfs images.
        Signing,
        /// The bootloader writes the machine's security floor in firmware
        /// storage, raises it, and refuses itself below it.
        Rollback,
        /// The firmware boots the bootloader signed with an enrolled key and
        /// refuses it tampered or unsigned, under UEFI Secure Boot.
        Secureboot,
        /// The softlockup watchdog reports a CPU wedged with interrupts off.
        Wedge,
        /// The kernel detects a VM generation change across a snapshot
        /// restore (`x86_64` only).
        Vmgenid,
        /// PCI Express hotplug of a device and of a disk behind root ports.
        Hotplug,
        /// The kernel's CET supervisor shadow stacks, under KVM (`x86_64`
        /// only).
        Cet,
        /// The TPM 2.0 driver behind `tpm-tis` and `tpm-crb` (`x86_64`
        /// only).
        Tpm,
        /// The machine shuts down for each cause: a reboot, the power button,
        /// and the death of each core or critical service.
        Shutdown,
        /// The debug port's transport, then the GDB stub driven by the host's
        /// GDB over it.
        DebugPort,
    }
}

value_enum! {
    /// The tester of a CI validate cell (`.github/workflows/build-test.yml`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Tester
    {
        /// The services harness.
        Svctest,
        /// The userspace harness.
        Usertest,
        /// The kernel-test harness.
        Ktest,
    }
}

value_enum! {
    /// A cause the `shutdown` case boots once for.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ShutdownCause
    {
        /// pwrmgr's `REBOOT`, which the `reboot` fixture sends: QMP's reason
        /// `guest-reset`.
        Reboot,
        /// The ACPI power button, pressed over QMP (`x86_64` only).
        PowerButton,
        /// The death of memmgr's thread, in an allocation.
        Memmgr,
        /// The death of a procmgr request worker, in a create.
        Procmgr,
        /// The death of procmgr's reaper thread, in a reap.
        ProcmgrReaper,
        /// The death of svcmgr's main thread.
        Svcmgr,
        /// The permanent death of devmgr's main thread.
        Devmgr,
        /// The permanent death of vfsd's main thread.
        Vfsd,
        /// The permanent death of logd's main thread: once per restart its
        /// budget allows and once more.
        Logd,
    }
}

impl ShutdownCause
{
    /// Whether the cause exists on `arch`: QEMU's riscv64 `virt` machine has
    /// no fixed power button.
    #[must_use]
    pub fn on(self, arch: Arch) -> bool
    {
        self != Self::PowerButton || arch == Arch::X86_64
    }
}

// ── KtestTiming ───────────────────────────────────────────────────────────────

args! {
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
}

// ── Symbolize ─────────────────────────────────────────────────────────────────

args! {
    pub struct SymbolizeArgs
    {
        /// The ELF image the addresses fall in (a sysroot binary, or its build
        /// output under `target/`). A stripped image's symbols are read from
        /// the symbols store's file of its build id.
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
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["binary", "kernel", "bias", "addresses"]
        )]
        pub log: Option<PathBuf>,

        /// The symbols store to read in place of the build's `symbols/`, such
        /// as a release's symbols archive unpacked. With `--log`, the images
        /// are the store's own files, named by its manifest, and the sysroot
        /// is not read.
        #[arg(long, value_name = "DIR")]
        pub symbols: Option<PathBuf>,
    }
}

/// The value parser of a hex address.
fn parse_hex_arg(text: &str) -> Result<u64, String>
{
    crate::symbolize::parse_hex(text).map_err(|err| format!("{err:#}"))
}

// ── LintDocs ──────────────────────────────────────────────────────────────────

args! {
    pub struct LintDocsArgs;
}

// ── CommitCheck ───────────────────────────────────────────────────────────────

args! {
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
}

// ── PrCheck ───────────────────────────────────────────────────────────────────

args! {
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
}

// ── CompareImages ─────────────────────────────────────────────────────────────

args! {
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
}

// ── ReviewLedger ──────────────────────────────────────────────────────────────

args! {
    pub struct ReviewLedgerArgs
    {
        /// The pull request's number: validate its records and write
        /// `ledger.json` beside them, or nothing when one is malformed.
        #[arg(conflicts_with = "release")]
        pub pr: Option<u64>,

        /// Validate the pull request's records alone and write nothing.
        #[arg(long, requires = "pr", conflicts_with = "release")]
        pub check: bool,

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
}

// ── ReleaseScope ──────────────────────────────────────────────────────────────

args! {
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
        #[arg(long, default_value_t = 200, value_parser = parse_page_entries)]
        pub page_entries: u64,

        /// Print page `<list>:<n>` (1-based) of `files`, `units`, or `issues`
        /// instead of the summary.
        #[arg(long, value_name = "LIST:N")]
        pub page: Option<String>,
    }
}

/// The value parser of `--page-entries`: a count of at least 1.
fn parse_page_entries(text: &str) -> Result<u64, String>
{
    let value: u64 = text
        .parse()
        .map_err(|err: std::num::ParseIntError| err.to_string())?;
    if value == 0
    {
        return Err(format!("{value} is not in 1..{}", u64::MAX));
    }
    Ok(value)
}

// ── IssueEdit / IssueFile ─────────────────────────────────────────────────────

args! {
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
}

args! {
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
        #[arg(long)]
        pub reason: Option<UnscheduledReason>,
    }
}

value_enum! {
    /// Why an Issue may stay without a milestone (docs/conventions.md
    /// § Milestones).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum UnscheduledReason
    {
        /// It needs hardware the project does not have.
        Hardware,
        /// It is not possible yet.
        NotPossible,
        /// Whether it belongs in the project is itself undecided.
        Undecided,
    }
}

// ── Orch ──────────────────────────────────────────────────────────────────────

args! {
    pub struct OrchArgs
    {
        #[command(subcommand)]
        pub command: OrchCommand,
    }
}

subcommands! {
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
}

args! {
    pub struct OrchWorkerArgs
    {
        /// The worker's name in the batch (for example `W3`).
        pub name: String,

        /// Remove the worker from the state.
        #[arg(
            long,
            conflicts_with_all = [
                "id", "model", "effort", "scope", "branch", "worktree", "pr", "phase", "status"
            ]
        )]
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
}

subcommands! {
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
}

subcommands! {
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
}

subcommands! {
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
}

// ── Hook ──────────────────────────────────────────────────────────────────────

args! {
    pub struct HookArgs
    {
        #[command(subcommand)]
        pub event: HookEvent,
    }
}

subcommands! {
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
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::argparse::Args as _;

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
        for command in ["build", "clean", "test", "crypto-vectors", "compare-images"]
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
        // A case or a cell boots, and admits each boot itself.
        assert!(build_host_of(&["xtask", "test", "kaslr"]).is_none());
        assert!(build_host_of(&["xtask", "test", "--cell", "usertest"]).is_none());
    }

    /// Parse `words` as the process's argv, the word `BAD` standing for an
    /// argument that is not valid UTF-8.
    #[cfg(unix)]
    fn parse_bytes(words: &[&str]) -> Result<Cli, crate::argparse::Error>
    {
        use std::ffi::{OsStr, OsString};
        use std::os::unix::ffi::OsStrExt as _;
        let argv: Vec<OsString> = words
            .iter()
            .map(|word| match *word
            {
                "BAD" => OsStr::from_bytes(b"out\xff.img").to_owned(),
                _ => OsString::from(word),
            })
            .collect();
        Cli::command().parse_os_into(&argv)
    }

    // Defect caught: an argument that is not valid UTF-8 converted lossily,
    // so a path option names another file and a text option takes an
    // altered value, where clap refused text that is not UTF-8.
    #[cfg(unix)]
    #[test]
    fn an_argument_that_is_not_utf8_is_refused_with_its_command_s_usage()
    {
        use crate::argparse::ErrorKind;
        for (words, usage) in [
            (
                &["xtask", "symbolize", "--kernel", "BAD", "0x1"][..],
                "Usage: xtask symbolize",
            ),
            (
                &["xtask", "build", "--arch", "BAD"][..],
                "Usage: xtask build",
            ),
            (&["xtask", "BAD", "build"][..], "Usage: xtask <COMMAND>"),
            (&["xtask", "host", "BAD"][..], "Usage: xtask host"),
            (&["xtask", "help", "BAD"][..], "Usage: xtask <COMMAND>"),
        ]
        {
            let error = parse_bytes(words)
                .err()
                .unwrap_or_else(|| panic!("{words:?} parsed"));
            assert_eq!(error.kind(), ErrorKind::InvalidUtf8, "{words:?}");
            assert_eq!(error.exit_code(), 2, "{words:?}");
            let text = error.to_string();
            assert!(
                text.starts_with("error: invalid UTF-8 was detected in one or more arguments\n\n"),
                "{text}"
            );
            assert!(text.contains(usage), "{words:?}: {text}");
        }
        // An error the parser meets first is the one reported.
        let first = parse_bytes(&["xtask", "build", "--no-such", "BAD"])
            .err()
            .unwrap();
        assert_eq!(first.kind(), ErrorKind::UnknownArgument);
        // The program's name may be any bytes.
        let named = parse_bytes(&["BAD", "build"]).unwrap();
        assert!(matches!(named.command, CliCommand::Build(_)));
    }
}
