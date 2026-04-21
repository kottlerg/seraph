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

    /// Build (if needed) and launch Seraph under QEMU.
    Run(RunArgs),

    /// Remove the sysroot (and optionally cargo target/).
    Clean(CleanArgs),

    /// Run Seraph unit tests on the host.
    Test(TestArgs),
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
    Devmgr,
    Vfsd,
    VirtioBlk,
    Fatfs,
    Crasher,
    Usertest,
    Svcmgr,
    Hello,
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

    /// Use the release build.
    #[arg(long)]
    pub release: bool,

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

    /// Skip the pre-launch build and use the existing sysroot / disk image
    /// as-is. Intended for tight loops — re-running the same image many
    /// times to shake out non-determinism (races, timer-dependent bugs)
    /// without paying cargo's fingerprint walk each iteration. Fails fast
    /// if the sysroot artifacts are missing; run `cargo xtask build` (or
    /// one `cargo xtask run` without the flag) to populate them first.
    #[arg(long)]
    pub no_build: bool,
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
