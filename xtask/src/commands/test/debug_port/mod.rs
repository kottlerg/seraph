// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/debug_port/mod.rs

//! Debug-port case: the debug port's transport ([`echo`]: GDB remote serial
//! protocol packets exchanged with the `debug-echo` fixture over the port),
//! then the GDB stub ([`gdb`]: the host's GDB in batch mode against the stub
//! over the port). One boot each, the second whatever the first's outcome;
//! the case fails naming the boots that failed.

mod echo;
mod gdb;

use crate::error::{Result, bail};

use crate::commands::test::cases::CaseArgs;
use crate::context::Context;

/// One boot of the case.
type Boot = fn(&Context, &CaseArgs) -> Result<()>;

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    let boots: [(&str, Boot); 2] = [("transport", echo::run), ("GDB stub", gdb::run)];
    let mut failed = Vec::new();
    for (name, boot) in boots
    {
        if let Err(e) = boot(ctx, args)
        {
            eprintln!("debug-port case: {name}: FAIL: {e:#}");
            failed.push(name);
        }
    }
    if !failed.is_empty()
    {
        bail!("debug-port case: FAIL for {}", failed.join(", "));
    }
    Ok(())
}
