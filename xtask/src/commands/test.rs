// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test.rs

//! Test command: run unit tests on the host target.
//!
//! Tests compile for the host (not a bare-metal target), so no --arch flag is
//! needed. The workspace Cargo.toml sets panic=abort for dev/release profiles;
//! host test builds override this implicitly via the test harness.

use std::process::Command;

use anyhow::Result;

use crate::cli::{TestArgs, TestComponent};
use crate::context::Context as BuildContext;
use crate::util::{run_cmd, step};

/// Entry point for `cargo xtask test`.
pub fn run(ctx: &BuildContext, args: &TestArgs) -> Result<()>
{
    match args.component
    {
        TestComponent::Boot =>
        {
            step("Testing bootloader (host)");
            run_cmd(cargo(ctx).args(["test", "-p", "boot"]))?;
        }
        TestComponent::Protocol =>
        {
            step("Testing boot protocol (host)");
            run_cmd(cargo(ctx).args(["test", "-p", "boot-protocol"]))?;
        }
        TestComponent::Kernel =>
        {
            step("Testing kernel (host)");
            run_cmd(cargo(ctx).args(["test", "-p", "kernel"]))?;
        }
        TestComponent::Init =>
        {
            step("Testing init (host)");
            run_cmd(cargo(ctx).args(["test", "-p", "init"]))?;
        }
        TestComponent::All =>
        {
            run_cmd(cargo(ctx).args(["test", "--workspace"]))?;
        }
    }

    step("Tests complete");
    Ok(())
}

fn cargo(ctx: &BuildContext) -> Command
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ctx.root);
    // Suppress all warnings in test builds. Many imports and stubs are
    // cfg-gated for bare-metal and appear unused on the host target.
    // Warnings are caught during normal `cargo xtask build` and `run`.
    cmd.env("RUSTFLAGS", "-A warnings");
    cmd
}
