// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/mod.rs

//! The `test` command: the unit tests ([`host`]); a host-driven QEMU case of
//! the registry ([`cases`]); or every case a CI validate cell runs.

pub mod cases;
mod cet;
mod debug_port;
mod host;
mod hotplug;
mod kaslr;
mod shutdown;
mod signing;
mod terminal;
mod tpm;
mod vmgenid;
mod wedge;

use crate::error::{Result, bail};

use crate::cli::TestArgs;
use crate::context::Context;

/// Entry point for `cargo xtask test`.
pub fn run(ctx: &Context, args: &TestArgs) -> Result<()>
{
    match (args.case, args.cell)
    {
        (Some(case), _) => cases::run_case(ctx, case, args),
        (None, Some(tester)) => cases::run_cell(ctx, tester, args),
        (None, None) =>
        {
            refuse_boot_options(args)?;
            host::run(ctx, args.component)
        }
    }
}

/// Refuse the options of a case's boots on a command line that runs the unit
/// tests: `main` admitted it as a build, and it boots nothing.
fn refuse_boot_options(args: &TestArgs) -> Result<()>
{
    let given = [
        (args.arch.is_some(), "--arch"),
        (args.cpus.is_some(), "--cpus"),
        (args.mem.is_some(), "--mem"),
        (args.release, "--release"),
        (args.host.alone, "--alone"),
        (args.host.timing, "--timing"),
        (args.host.grant.is_some(), "--grant"),
    ];
    if let Some((_, flag)) = given.iter().find(|(given, _)| *given)
    {
        bail!("{flag} applies to a case or a cell, and this command line names neither");
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::argparse::Args as _;
    use crate::cli::{Cli, CliCommand};

    // Defect caught: a boot option given to the unit tests accepted and
    // ignored, so `test --arch riscv64` reads as a riscv64 run it is not.
    #[test]
    fn the_unit_tests_refuse_a_boot_option()
    {
        for flag in [
            &["--arch", "riscv64"][..],
            &["--release"],
            &["--alone"],
            &["--grant", "w"],
        ]
        {
            let mut line = vec!["xtask", "test"];
            line.extend_from_slice(flag);
            let CliCommand::Test(args) = Cli::try_parse_from(&line).unwrap().command
            else
            {
                unreachable!()
            };
            refuse_boot_options(&args).unwrap_err();
        }
        let CliCommand::Test(args) = Cli::try_parse_from([
            "xtask",
            "test",
            "--component",
            "kernel",
            "--wait-host",
            "30",
        ])
        .unwrap()
        .command
        else
        {
            unreachable!()
        };
        refuse_boot_options(&args).unwrap();
    }
}
