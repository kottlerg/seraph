// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Test-phase registry, organised by **services-tier surface under
//! test**.
//!
//! Rule (durable, codifies the #21 structural refactor):
//!
//! > **One module per services-tier surface (or kernel/runtime
//! > surface) under test. New service ⇒ new module.**
//!
//! Adding tests for an as-yet-unwritten service is a new file under
//! this directory plus one line in [`all`] to register the module's
//! phases at the right point in the ordered sequence. Files don't
//! grow unboundedly because each is scoped to one surface.
//!
//! ### Ordering constraints (encoded by composition order in `all()`)
//!
//! 1. [`startup`] first — argv/env/stack/TLS bring-up before anything
//!    else touches them.
//! 2. [`fs_ipc`] and [`fs_std`] near the end (but before [`pwrmgr`]).
//! 3. `fs_open_relative_phase` last inside [`fs_ipc`]: it installs a
//!    process-global `current_dir_cap` whose cap-derivation pressure
//!    on TCG-emulated arches affects subsequent phases.
//! 4. `pwrmgr_shutdown_phase` is NOT in the registry — `main.rs`
//!    calls it explicitly after [`run_all`](crate::runner::run_all)
//!    returns and after the `ALL TESTS PASSED` marker is emitted.
//! 5. [`memmgr::identity`] last: the all-RAM-accounted identity only
//!    closes once init's reap donations reach memmgr, which races
//!    svctest startup. Running it last maximises the chance the
//!    donations have landed; the phase polls to close the residual race.

use crate::runner::Phase;

pub mod devmgr;
pub mod exit_code;
pub mod fs_ipc;
pub mod fs_std;
pub mod memmgr;
pub mod namespace;
pub mod pager;
pub mod pipes;
pub mod process_faults;
pub mod procmgr;
pub mod pwrmgr;
pub mod random;
pub mod recv_guard;
pub mod shmem;
pub mod startup;
pub mod threading;
pub mod timed;

/// Ordered phase list. Order encodes cross-module dependencies (see
/// module-level docstring above).
pub fn all() -> Vec<Phase>
{
    let mut out: Vec<Phase> = Vec::new();
    out.extend_from_slice(startup::main_startup());
    out.extend_from_slice(memmgr::phases());
    out.extend_from_slice(threading::phases());
    out.extend_from_slice(procmgr::spawn_only());
    out.extend_from_slice(process_faults::phases());
    out.extend_from_slice(exit_code::phases());
    out.extend_from_slice(random::phases());
    out.extend_from_slice(recv_guard::phases());
    out.extend_from_slice(devmgr::phases());
    out.extend_from_slice(pager::phases());
    out.extend_from_slice(shmem::phases());
    out.extend_from_slice(pipes::phases());
    out.extend_from_slice(namespace::early());
    out.extend_from_slice(fs_ipc::phases_pre_relative());
    out.extend_from_slice(fs_std::phases());
    out.extend_from_slice(namespace::late());
    out.extend_from_slice(procmgr::command_phases());
    out.extend_from_slice(startup::late());
    out.extend_from_slice(fs_ipc::relative_only());
    out.extend_from_slice(pwrmgr::deny_only());
    out.extend_from_slice(timed::phases());
    out.extend_from_slice(memmgr::identity());
    out
}
