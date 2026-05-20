// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Phase registry and driver.
//!
//! Phases are ordered `fn(&Caps)` entries collected from each
//! `phases::<surface>::phases()`. The runner logs a uniform envelope
//! around each invocation so phase boundaries are visible in the boot
//! log even when individual phases self-skip on missing caps.

use crate::bootstrap::Caps;

/// One test phase: a name (for logging) and a function with uniform
/// signature.
#[derive(Clone, Copy)]
pub struct Phase
{
    pub name: &'static str,
    pub run: fn(&Caps),
}

/// Invoke every phase in order. Failures inside a phase panic through
/// the std-overlay panic handler.
pub fn run_all(phases: &[Phase], caps: &Caps)
{
    for p in phases
    {
        std::os::seraph::log!("phase={} starting", p.name);
        (p.run)(caps);
        std::os::seraph::log!("phase={} passed", p.name);
    }
}
