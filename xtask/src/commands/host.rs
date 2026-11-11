// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/host.rs

//! `host`: the shared host's state as the launch rules read it.
//!
//! The rules themselves, and the admission every build and boot passes, are
//! `crate::host_lock`'s; this command only prints what they read.

use anyhow::Result;

use crate::cli::{HostCommand, HostCommandArgs};
use crate::context::Context;

/// Entry point for `cargo xtask host`.
pub fn run(ctx: &Context, args: &HostCommandArgs) -> Result<()>
{
    match args.command
    {
        HostCommand::Status => crate::host_lock::print_status(ctx),
    }
}
