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
//! 1. Add a variant to `cli::CliCommand` and a corresponding `args!` struct
//!    in `cli.rs`, and name it in `CliCommand::build_host`: a command that
//!    compiles takes `HostArgs` and is admitted there as a build. Add its
//!    command lines to the reference corpus (xtask/README.md § Command-line
//!    parsing).
//! 2. Create `commands/<name>.rs` with a `pub fn run(ctx, args) -> Result<()>`,
//!    or add a `pub fn run_<name>` to the module that holds its sibling commands.
//!    (`hook::run` returns nothing: a hook answers every event and never fails.)
//! 3. Add a match arm in `main` below.
//! 4. Re-export the module in `commands/mod.rs`.

// `symbolize`, the riscv64 kernel frame check and `compare-images` read ELF,
// PE and DWARF with the `object`, `addr2line` and `rustc_demangle` crates the
// pinned toolchain's sysroot ships for std's backtraces, so they have no Cargo
// entry (docs/coding-standards.md § Dependencies). Only a build against the
// prebuilt std reaches them; `cargo xtask test` lints xtask that way. The std
// of a `*-windows-msvc` host carries no `object` or `addr2line`, so xtask
// builds on Windows with the GNU host toolchain (docs/build-system.md
// § Toolchain).
#![feature(rustc_private)]
// The host OS random source (`std::random::SystemRng`) a local signing
// identity's seeds are drawn from (src/signing).
#![feature(random)]
#[cfg(all(windows, target_env = "msvc"))]
compile_error!(
    "xtask needs the toolchain sysroot's `object` and `addr2line`, which a *-windows-msvc host's \
     std does not carry: build it with the GNU host toolchain (docs/build-system.md § Toolchain)"
);

extern crate addr2line;
extern crate object;
extern crate rustc_demangle;

mod accel;
mod arch;
mod argparse;
mod benchmark;
mod breakpoint_kill;
mod bundle;
mod cli;
mod commands;
mod context;
mod crash_check;
mod crash_log;
mod debug_stub;
mod diag;
mod disk;
mod error;
mod esp;
mod fat;
mod fat_read;
mod firmware;
mod fs_compat;
mod gh;
mod gpt;
mod guest;
mod host_lock;
mod image_check;
mod path_account;
mod qemu;
mod qemu_gdb;
mod qmp;
mod regex;
mod rust_src;
mod secure_boot;
mod signing;
mod socket_dir;
mod stack_sizes;
mod symbolize;
mod sys;
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

    // Install a Ctrl+C handler that only records the signal, so SIGINT
    // terminates the inner subprocess (cargo, QEMU) without killing xtask
    // itself, and ends a host-lock wait. Allows TerminalGuard::drop and
    // error propagation to run on Ctrl+C.
    if let Err(err) = term::signal::install()
    {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }

    if let Some(host) = cli.command.build_host()
        && let Err(err) = host_lock::admit_build(&ctx, host)
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
        CliCommand::CryptoVectors(args) => commands::crypto_vectors::run(&ctx, args),
        CliCommand::Fuzz(args) => commands::fuzz::run(&ctx, args),
        CliCommand::Kani(args) => commands::kani::run(&ctx, args),
        CliCommand::KtestTiming(args) => commands::ktest_timing::run(&ctx, args),
        CliCommand::PathAccount(args) => commands::path_account::run(&ctx, args),
        CliCommand::BenchCheck(args) => commands::bench_check::run(&ctx, args),
        CliCommand::BenchBaseline(args) => commands::bench_baseline::run(&ctx, args),
        CliCommand::Symbolize(args) => commands::symbolize::run(&ctx, args),
        CliCommand::Mkdisk(args) => commands::mkdisk::run(&ctx, args),
        CliCommand::TrustRequest(args) => commands::trust_request::run(&ctx, args),
        CliCommand::CaptureAcpi(args) => commands::capture_acpi::run(&ctx, args),
        CliCommand::LintDocs(args) => commands::lint_docs::run(&ctx, args),
        CliCommand::CommitCheck(args) => commands::pr_check::run_commit_check(&ctx, args),
        CliCommand::PrCheck(args) => commands::pr_check::run_pr_check(&ctx, args),
        CliCommand::CompareImages(args) => commands::compare_images::run(&ctx, args),
        CliCommand::ReviewLedger(args) => commands::review::run_ledger(&ctx, args),
        CliCommand::ReleaseScope(args) => commands::release_scope::run(&ctx, args),
        CliCommand::ThreatScope(args) => commands::threat_scope::run(&ctx, args),
        CliCommand::IssueEdit(args) => commands::issue::run_edit(&ctx, args),
        CliCommand::IssueFile(args) => commands::issue::run_file(&ctx, args),
        CliCommand::Orch(args) => commands::orch::run(&ctx, args),
        CliCommand::Host(args) => commands::host::run(&ctx, args),
        CliCommand::Hook(args) =>
        {
            commands::hook::run(&ctx, args);
            Ok(())
        }
    };

    if let Err(err) = result
    {
        // `{:#}` prints the whole chain: each `context` above its cause.
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
