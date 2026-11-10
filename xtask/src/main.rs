// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/main.rs

//! xtask — build task runner for Seraph.
//!
//! Invoke via `cargo xtask <command>`. Replaces `build.sh`, `run.sh`,
//! `clean.sh`, and `test.sh`.
//!
//! # Adding a new command
//!
//! 1. Add a variant to `cli::CliCommand` and a corresponding `Args` struct in
//!    `cli.rs`.
//! 2. Create `commands/<name>.rs` with a `pub fn run(ctx, args) -> Result<()>`,
//!    or add a `pub fn run_<name>` to the module that holds its sibling commands.
//! 3. Add a match arm in `main` below.
//! 4. Re-export the module in `commands/mod.rs`.

// multiple_crate_versions: duplicate transitive versions (bitflags, hashbrown,
// windows-sys, wit-bindgen) come from third-party host deps (clap, gpt, fatfs,
// libc, which); not resolvable without upstream releases.
#![allow(clippy::multiple_crate_versions)]

use clap::Parser;

mod accel;
mod arch;
mod bundle;
mod cli;
mod commands;
mod context;
mod crash_log;
mod debug_stub;
mod diag;
mod disk;
mod firmware;
mod fs_compat;
mod gh;
mod qemu;
mod qmp;
mod rust_src;
mod symbolize;
mod sysroot;
mod tasklist;
mod term;
mod timing;
mod util;

use cli::{Cli, CliCommand};
use context::Context;

fn main()
{
    let cli = Cli::parse();
    let ctx = match Context::from_manifest_dir()
    {
        Ok(ctx) => ctx,
        Err(err) =>
        {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };

    // Install a no-op Ctrl+C handler so SIGINT terminates the inner
    // subprocess (cargo, QEMU) without killing xtask itself. Allows
    // TerminalGuard::drop and error propagation to run on Ctrl+C.
    if let Err(err) = term::signal::install()
    {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }

    let result = match &cli.command
    {
        CliCommand::Build(args) => commands::build::run(&ctx, args),
        CliCommand::Run(args) => commands::run::run(&ctx, args),
        CliCommand::Clean(args) => commands::clean::run(&ctx, args),
        CliCommand::Test(args) => commands::test::run(&ctx, args),
        CliCommand::RunParallel(args) => commands::run_parallel::run(&ctx, args),
        CliCommand::KtestTiming(args) => commands::ktest_timing::run(&ctx, args),
        CliCommand::Symbolize(args) => commands::symbolize::run(&ctx, args),
        CliCommand::Mkdisk(args) => commands::mkdisk::run(&ctx, args),
        CliCommand::ComposeBundle(args) => commands::compose_bundle::run(&ctx, args),
        CliCommand::TestTerminal(args) => commands::test_terminal::run(&ctx, args),
        CliCommand::TestVmgenid(args) => commands::test_vmgenid::run(&ctx, args),
        CliCommand::TestKaslr(args) => commands::test_kaslr::run(&ctx, args),
        CliCommand::TestLogdReclaim(args) => commands::test_logd_reclaim::run(&ctx, args),
        CliCommand::TestCrashReport(args) => commands::test_crash_report::run(args),
        CliCommand::TestMapRedo(args) => commands::test_map_redo::run(&ctx, args),
        CliCommand::TestDebugPort(args) => commands::test_debug_port::run(&ctx, args),
        CliCommand::TestGdb(args) => commands::test_gdb::run(&ctx, args),
        CliCommand::LintDocs(args) => commands::lint_docs::run(&ctx, args),
        CliCommand::CommitCheck(args) => commands::pr_check::run_commit_check(&ctx, args),
        CliCommand::PrCheck(args) => commands::pr_check::run_pr_check(&ctx, args),
        CliCommand::ReviewCheck(args) => commands::review::run_check(&ctx, args),
        CliCommand::ReviewLedger(args) => commands::review::run_ledger(&ctx, args),
        CliCommand::IssueEdit(args) => commands::issue::run_edit(&ctx, args),
        CliCommand::IssueFile(args) => commands::issue::run_file(&ctx, args),
        CliCommand::Orch(args) => commands::orch::run(&ctx, args),
    };

    if let Err(err) = result
    {
        // Print the full error chain (anyhow includes context from .context() calls).
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
