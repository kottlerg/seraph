// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/reentry.rs

//! argv-driven child-mode dispatch.
//!
//! Several phases respawn `/tests/svctest` with a role token as argv[1]
//! (some roles take further arguments after it, e.g. `blobs-large-child`'s
//! long argv token) to exercise child-side behaviour: namespace and
//! `/programs`-subtree attenuation, cwd-cap delivery, argv/env delivery,
//! exit-code propagation, per-process randomness and ASLR divergence,
//! `Child` kill and drop teardown, procmgr's teardown of a child whose create
//! reply it cannot deliver, procmgr's death forward to logd, procmgr's post
//! of a process's end to its end queue and, once, to its death relay, the fs
//! release handler's cookie matching, fatfs's release of the open of a
//! killed client and of one whose open reply it cannot deliver, memmgr's hold
//! on a dead child's frame that a live kernel object still occupies, memmgr's hold
//! of a child to the memory max its creator set, its commitment of a heap's
//! growth, memmgr's eviction of a child's cold pages and their restore, a child's
//! attachment of a memory object, its call of an executable one, and what a mapped cache page reads across a forced
//! unmount. The
//! `reboot` role is the one not spawned by a phase: svcmgr launches it from
//! the `reboot` test recipe `cargo xtask test-reboot` stages.
//! The child-mode function for each role lives in the phase module that
//! spawns it; `dispatch` consults each module's `reentry_main(role)` so a
//! new role is registered alongside its phase, not in a central switch.
//!
//! A module's `reentry_main` diverges on a matching role, by exiting
//! (`std::process::exit`) or, for `park-child`, `reclaim-child`, and
//! `open-reclaim-child`, by parking until its spawner tears it down, and returns on a miss;
//! `dispatch` cascades through the modules and returns to its caller only
//! when no module took control.

use crate::phases;

/// If any phase module's `reentry_main` matches `role`, control never
/// returns (the child exits by its exit-code convention, or parks until its
/// spawner tears it down).
/// Otherwise returns normally so the parent test sequence proceeds.
pub fn dispatch(role: &str)
{
    phases::namespace::reentry_main(role);
    phases::procmgr::reentry_main(role);
    phases::process_tree::reentry_main(role);
    phases::fs_std::reentry_main(role);
    phases::fs_opens::reentry_main(role);
    phases::exit_code::reentry_main(role);
    phases::random::reentry_main(role);
    phases::memmgr::reentry_main(role);
    phases::budget::reentry_main(role);
    phases::node_handle::reentry_main(role);
    phases::heap_commit::reentry_main(role);
    phases::discard::reentry_main(role);
    phases::memory_objects::reentry_main(role);
    phases::memory_object_text::reentry_main(role);
    phases::swap::reentry_main(role);
    phases::swap_commit::reentry_main(role);
    phases::unmount::reentry_main(role);
    phases::pwrmgr::reentry_main(role);
    phases::logd_restart::reentry_main(role);
}
