// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/service-modes/src/main.rs

//! svctest's shared service fixture: the services svctest's recipes have
//! svcmgr start in the service role whose checks need no image of their own,
//! one mode each, chosen by the first argument the recipe's `argv` gives
//! (services/fixtures/service-modes/README.md). A mode's further arguments
//! follow its name. Each mode is a module with its own `main`, which runs
//! from this binary's `main` before anything else, so it starts in the state
//! a binary of its own would.

mod crasher;
mod memhog;
mod stopsrc;

/// Where the build installs this binary, which a mode that spawns itself
/// starts.
pub(crate) const PATH: &str = "/tests/fixtures/service-modes";

fn main()
{
    let mode = std::env::args().nth(1);
    match mode.as_deref()
    {
        Some("crasher") => crasher::main(),
        Some("memhog") => memhog::main(),
        Some("stopsrc") => stopsrc::main(),
        _ =>
        {
            std::os::seraph::log::register_name(b"service-modes");
            std::os::seraph::log!(error: "no mode {mode:?}");
        }
    }
}
