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
    CmosRtc,
    GoldfishRtc,
    Fatfs,
    Crasher,
    Usertest,
    Svcmgr,
    Pwrmgr,
    Timed,
    Hello,
    Fsbench,
    Pipefault,
    Stackoverflow,
    Stdiotest,
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

    /// Show all serial output including pre-boot firmware noise (filtered by default).
    ///
    /// By default, output is suppressed until the first line containing
    /// '[--------] boot:', hiding UEFI/OpenSBI debug spam.
    #[arg(long)]
    pub verbose: bool,

    /// Number of vCPUs to expose to the guest (QEMU -smp).
    #[arg(long, default_value = "4")]
    pub cpus: u32,
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
    /// the run is classified PASS. The default matches the unique terminal
    /// marker emitted by both ktest (`ktest: ALL TESTS PASSED`) and
    /// usertest (`[usertest] ALL TESTS PASSED`); override for other rootfs
    /// configurations.
    #[arg(long, default_value = "ALL TESTS PASSED")]
    pub pass: String,

    /// Regex marking a failed run. On match the log is preserved as
    /// FAIL-<run>.log. Failure takes precedence over success.
    #[arg(long)]
    pub fail: Option<String>,
}
