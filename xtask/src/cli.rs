// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! cli.rs
//!
//! Clap derive structs for the xtask CLI.
//!
//! Add a new top-level command by adding a variant to `Command` and a
//! corresponding `Args` struct below, then handle it in `main.rs`.

use clap::{Parser, Subcommand, ValueEnum};

use crate::arch::Arch;
use crate::bundle::Harness;

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

    /// Mirror `rootfs/` into the sysroot, re-synthesise test fixtures,
    /// and regenerate `disk.img` without invoking cargo. Used to refresh
    /// the boot image after `rootfs/` or sysroot files were edited
    /// outside the cargo flow (e.g. staging a test recipe). Requires an
    /// arch-tagged sysroot from a prior `cargo xtask build`.
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

    /// Build only one component (default: all).
    #[arg(long, default_value = "all")]
    pub component: BuildComponent,

    /// Emit debuginfo (`debug = 2`, `opt-level = 1`) for the named
    /// component(s) only, within the active profile (default or `--release`).
    /// Comma-separated, e.g. `--debug kernel,procmgr`; names match
    /// `--component`. Only components in the current build are affected.
    #[arg(long, value_delimiter = ',')]
    pub debug: Vec<BuildComponent>,

    /// Skip `cargo fmt` and per-component `cargo check` (clippy). `cargo
    /// xtask run` sets this internally to keep the tight edit → rebuild →
    /// launch loop responsive — an unchanged tree would otherwise pay for
    /// ~2× cargo invocations per component (check + build) on every
    /// re-run. Use `cargo xtask build` when you want the full lint pass.
    #[arg(long, hide = true)]
    pub skip_lints: bool,
}

/// Components that can be built individually.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum BuildComponent
{
    Boot,
    Kernel,
    Init,
    Ktest,
    Procmgr,
    Memmgr,
    Devmgr,
    Vfsd,
    VirtioBlk,
    Serial,
    Framebuffer,
    CmosRtc,
    GoldfishRtc,
    Fatfs,
    Crasher,
    Svctest,
    Usertest,
    Svcmgr,
    Pwrmgr,
    Timed,
    Hello,
    HelloTester,
    FbCharset,
    Terminal,
    Fsbench,
    Pipefault,
    Shell,
    ShellTester,
    Stackoverflow,
    Demandpaged,
    Stdiotest,
    StdiotestTester,
    Threadstack,
    ThreadstackTester,
    Threadchurn,
    ThreadchurnTester,
    All,
}

// ── Run ───────────────────────────────────────────────────────────────────────

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
    /// (e.g. adding a test recipe and removing a default one) when the
    /// additive re-mirror would otherwise restore the removed file.
    #[arg(long)]
    pub repack_only: bool,
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
/// hardware-trap path; `PANIC( at |: )` covers the Rust `#[panic_handler]`.
/// The benign `USERSPACE FAULT` path matches none of these.
pub const DEFAULT_FAIL_REGEX: &str = r"SOME TESTS FAILED|KERNEL EXCEPTION|FATAL:|PANIC( at |: )";

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

    /// Regex marking a successful run. On match the log is discarded and
    /// the run is classified PASS. The default matches the cross-harness
    /// terminal marker `[<harness>] ALL TESTS PASSED` standardised in
    /// [`docs/testing.md`](../../docs/testing.md); override for other
    /// rootfs configurations.
    #[arg(long, default_value = "ALL TESTS PASSED")]
    pub pass: String,

    /// Regex marking a failed run. On match the log is preserved as
    /// FAIL-<run>.log. Failure takes precedence over success. The default
    /// matches the cross-harness terminal marker
    /// `[<harness>] SOME TESTS FAILED` ([`docs/testing.md`](../../docs/testing.md)) plus the kernel's
    /// own death markers, so a crash classifies as FAIL rather than HANG: a
    /// hardware trap prints `KERNEL EXCEPTION` then `FATAL:`
    /// (`core/kernel/src/main.rs` `fatal()`), and a Rust `panic!` prints
    /// `PANIC at`/`PANIC:` (the `#[panic_handler]`). The benign userspace
    /// fault path prints `USERSPACE FAULT`, which none of these match.
    /// Override with a never-matching pattern (e.g. `'$.^'`) to disable.
    #[arg(long, default_value = DEFAULT_FAIL_REGEX)]
    pub fail: String,

    /// Grace window, in seconds, after the first `--fail` match before the
    /// run is SIGKILLed. A kernel fault dump is multi-line and may be
    /// followed by secondary-CPU faults; killing on the first matching byte
    /// truncates the diagnostics. The run is killed at whichever is first:
    /// this window, or the `--timeout` deadline. 0 kills on the next poll
    /// after the match.
    #[arg(long, default_value = "10")]
    pub fail_grace_secs: u64,
}
