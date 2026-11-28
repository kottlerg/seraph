// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/main.rs

//! svctest's shared program fixture: the processes svctest's phases, and
//! ubench's `fault_rate`, spawn in the program role whose checks need no image
//! of their own, one mode each, chosen by the first argument
//! (services/fixtures/program-modes/README.md).
//! A mode's further arguments follow its name. Each mode is a module with
//! its own `main`, which runs from this binary's `main` before anything
//! else, so it starts in the state a binary of its own would.

use std::process::ExitCode;

mod capexhaust;
mod deadline;
mod demandpaged;
mod faultstorm;
mod narrow;
mod pipefault;
mod pipestress;
mod relrofault;
mod stackoverflow;
mod threadchurn;
mod threadstack;

/// Where the build installs this binary, which a mode that spawns itself
/// starts.
pub(crate) const PATH: &str = "/tests/fixtures/programs/program-modes";

/// Exit code: the first argument names no mode.
const EXIT_NO_MODE: u8 = 2;

fn main() -> ExitCode
{
    let mode = std::env::args().nth(1);
    match mode.as_deref()
    {
        Some("capexhaust") => capexhaust::main(),
        Some("deadline") =>
        {
            deadline::main();
            ExitCode::SUCCESS
        }
        Some("demandpaged") => demandpaged::main(),
        Some("faultstorm") => faultstorm::main(),
        Some("narrow") =>
        {
            narrow::main();
            ExitCode::SUCCESS
        }
        Some("pipefault") =>
        {
            pipefault::main();
            ExitCode::SUCCESS
        }
        Some("pipestress") =>
        {
            pipestress::main();
            ExitCode::SUCCESS
        }
        Some("relrofault") =>
        {
            relrofault::main();
            ExitCode::SUCCESS
        }
        Some("stackoverflow") =>
        {
            stackoverflow::main();
            ExitCode::SUCCESS
        }
        Some("threadchurn") => threadchurn::main(),
        Some("threadstack") => threadstack::main(),
        _ =>
        {
            eprintln!("program-modes: no mode {mode:?}");
            ExitCode::from(EXIT_NO_MODE)
        }
    }
}
