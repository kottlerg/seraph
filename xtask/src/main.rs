// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! xtask — build task runner for Seraph.
//!
//! Invoke via `cargo xtask <command>`. Replaces `build.sh`, `run.sh`,
//! `clean.sh`, and `test.sh`.
//!
//! # Adding a new command
//!
//! 1. Add a variant to `cli::CliCommand` and a corresponding `Args` struct in
//!    `cli.rs`.
//! 2. Create `commands/<name>.rs` with a `pub fn run(ctx, args) -> Result<()>`.
//! 3. Add a match arm in `main` below.
//! 4. Re-export the module in `commands/mod.rs`.

use clap::Parser;

mod accel;
mod arch;
mod cli;
mod commands;
mod context;
mod disk;
mod firmware;
mod qemu;
mod rust_src;
mod sysroot;
mod term;
mod util;

use cli::{Cli, CliCommand};
use context::Context;

fn main()
{
    let cli = Cli::parse();
    let ctx = Context::from_manifest_dir();

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
    };

    if let Err(err) = result
    {
        // Print the full error chain (anyhow includes context from .context() calls).
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
