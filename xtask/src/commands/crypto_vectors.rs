// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/crypto_vectors.rs

//! Crypto-vectors command: regenerate the reference vectors of
//! `shared/crypto/testkit` with OpenSSL, or check that they regenerate
//! byte-identically.
//!
//! The command builds and runs the testkit's `crypto-reference-vectors`
//! binary for the host; xtask does not depend on the testkit.

use std::process::Command;

use crate::error::Result;

use crate::cli::CryptoVectorsArgs;
use crate::context::Context as BuildContext;
use crate::util::{run_cmd, step};

/// Entry point for `cargo xtask crypto-vectors`.
pub fn run(ctx: &BuildContext, args: &CryptoVectorsArgs) -> Result<()>
{
    step(
        if args.check
        {
            "Checking the crypto reference vectors"
        }
        else
        {
            "Regenerating the crypto reference vectors"
        },
    );
    run_cmd(
        Command::new("cargo")
            .current_dir(&ctx.root)
            .args(generator_args(args)),
    )
}

/// The `cargo` arguments that build and run the generator.
fn generator_args(args: &CryptoVectorsArgs) -> Vec<&'static str>
{
    let mut cargo = vec![
        "run",
        "--package",
        "crypto-testkit",
        "--bin",
        "crypto-reference-vectors",
    ];
    if args.check
    {
        cargo.extend(["--", "--check"]);
    }
    cargo
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cli::HostArgs;

    #[test]
    fn check_reaches_the_generator_and_not_cargo()
    {
        let mut args = CryptoVectorsArgs {
            check: true,
            host: HostArgs::default(),
        };
        let cargo = generator_args(&args);
        let split = cargo.iter().position(|a| *a == "--").unwrap();
        assert_eq!(&cargo[split + 1..], ["--check"]);
        args.check = false;
        assert!(!generator_args(&args).contains(&"--check"));
    }
}
