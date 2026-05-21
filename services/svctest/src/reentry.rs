// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! argv-driven child-mode dispatch.
//!
//! Several phases respawn `/bin/svctest` with a single argv token to
//! exercise child-side behaviour (namespace attenuation propagation,
//! cwd-cap delivery, `/bin`-subtree attenuation). The child-mode
//! function for each role lives in the phase module that spawns it;
//! `dispatch` consults each module's `reentry_main(role)` so a new
//! role is registered alongside its phase, not in a central switch.
//!
//! A module's `reentry_main` diverges (`std::process::exit`) on a
//! matching role and returns on a miss; `dispatch` cascades through
//! the modules and returns to its caller only when no module took
//! control.

use crate::phases;

/// If any phase module's `reentry_main` matches `role`, control never
/// returns (the child process exits via its exit-code convention).
/// Otherwise returns normally so the parent test sequence proceeds.
pub fn dispatch(role: &str)
{
    phases::namespace::reentry_main(role);
    phases::procmgr::reentry_main(role);
}
