// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/mod.rs

//! Test-phase registry. The module layout (one module per surface under
//! test) is specified in `services/svctest/README.md` § Source Layout; a new
//! module registers its phases with one line in [`all`], at the point the
//! ordering constraints below require.
//!
//! ### Ordering constraints (encoded by composition order in `all()`)
//!
//! 1. [`startup`] first — argv/env/stack/TLS bring-up before anything
//!    else touches them.
//! 2. [`fs_opens`], [`fs_ipc`], [`fs_std`], and [`fs_faults`] near the end
//!    (but before [`pwrmgr`]). [`fs_opens`] comes before
//!    [`fs_ipc`]: its eviction phase needs `/data`'s page cache cold (slots
//!    not yet provisioned), and it writes the slot-reuse file that
//!    `fs_ipc`'s slot-reuse phase reads and removes.
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
//! 6. [`procmgr::init_reap`] just before it, for the same reason: it waits
//!    for init's reap, and polls for it.
//! 7. [`procmgr::logd_forward`] just after [`procmgr::spawn_only`]: it
//!    reads its child's retired slot from logd before many other children
//!    die and retire theirs, and polls until logd has drained the death.
//! 8. [`unmount`] after every phase that uses `/data` or the cwd: it
//!    unmounts the data partition, killing every cap on it, before it
//!    mounts it again and sets the cwd to it again.
//! 9. [`logd_restart`] after every phase that reads logd's slots or
//!    history before it ([`procmgr::logd_forward`], [`log_client`]): it
//!    kills logd, whose next instance holds a fresh table, and runs the
//!    [`procmgr::logd_forward`] check again against it.
//! 10. [`logd_sinks`] after [`drivers`] and every phase that uses the
//!     framebuffer driver: it kills that driver, whose restart devmgr serves
//!     at the class's next ordinal, and requires the restart at ordinal 1.
//!     The `drivers_hwrng_restart` phase last inside [`drivers`], after the
//!     phases that read the entropy driver, for the same reason.
//! 11. [`entropyd`] early, before [`logd_restart`]: it reads entropyd's
//!     first-contribution line, logged once at entropyd's start, from logd's
//!     history, which a later phase's lines could evict and which the next
//!     logd instance does not hold.
//! 12. [`swap`] after every phase that uses the `memhog` fixture ([`svcmgr`],
//!     [`oom`], [`logd_restart`]): it holds the level at `CRITICAL` while it
//!     restores chunks from the restore headroom, which on a slow host outlasts
//!     oomd's grace. oomd then stops memhog, and svcmgr's restart of it, made
//!     while the level still reads `CRITICAL`, fails, which leaves memhog down
//!     with its endpoint still published.

use crate::runner::Phase;

pub mod acpi;
pub mod budget;
pub mod crash;
pub mod devmgr;
pub mod discard;
pub mod drivers;
pub mod entropyd;
pub mod exit_code;
pub mod fs_faults;
pub mod fs_ipc;
pub mod fs_opens;
pub mod fs_std;
pub mod heap_commit;
pub mod layout;
pub mod log_client;
pub mod logd_restart;
pub mod logd_sinks;
pub mod memmgr;
pub mod namespace;
pub mod node_handle;
pub mod oom;
pub mod pager;
pub mod pipes;
pub mod process_faults;
pub mod process_tree;
pub mod procmgr;
pub mod pwrmgr;
pub mod random;
pub mod recv_guard;
pub mod recv_pool;
pub mod sessiond;
pub mod shmem;
pub mod startup;
pub mod svcmgr;
pub mod swap;
pub mod threading;
pub mod timed;
pub mod unmount;
pub mod vfsd;

/// Ordered phase list. Order encodes cross-module dependencies (see
/// module-level docstring above).
pub fn all() -> Vec<Phase>
{
    let mut out: Vec<Phase> = Vec::new();
    out.extend_from_slice(startup::main_startup());
    out.extend_from_slice(memmgr::phases());
    out.extend_from_slice(layout::phases());
    out.extend_from_slice(threading::phases());
    out.extend_from_slice(procmgr::spawn_only());
    out.extend_from_slice(procmgr::logd_forward());
    out.extend_from_slice(process_faults::phases());
    out.extend_from_slice(exit_code::phases());
    out.extend_from_slice(random::phases());
    out.extend_from_slice(entropyd::phases());
    out.extend_from_slice(recv_guard::phases());
    out.extend_from_slice(recv_pool::phases());
    out.extend_from_slice(devmgr::phases());
    out.extend_from_slice(pager::phases());
    out.extend_from_slice(budget::phases());
    out.extend_from_slice(node_handle::phases());
    out.extend_from_slice(heap_commit::phases());
    out.extend_from_slice(discard::phases());
    out.extend_from_slice(shmem::phases());
    out.extend_from_slice(pipes::phases());
    out.extend_from_slice(namespace::early());
    // fs_opens runs while /data's cache is still cold (its eviction phase's
    // CSpace case needs slots not yet provisioned) and writes the file the
    // slot-reuse phase of fs_ipc reads and removes.
    out.extend_from_slice(fs_opens::phases());
    out.extend_from_slice(fs_ipc::phases_pre_relative());
    out.extend_from_slice(fs_std::phases());
    out.extend_from_slice(fs_faults::phases());
    out.extend_from_slice(namespace::late());
    out.extend_from_slice(procmgr::command_phases());
    out.extend_from_slice(process_tree::phases());
    out.extend_from_slice(startup::late());
    out.extend_from_slice(fs_ipc::relative_only());
    out.extend_from_slice(pwrmgr::deny_only());
    out.extend_from_slice(svcmgr::phases());
    out.extend_from_slice(sessiond::phases());
    out.extend_from_slice(oom::phases());
    out.extend_from_slice(timed::phases());
    out.extend_from_slice(log_client::phases());
    out.extend_from_slice(logd_restart::phases());
    out.extend_from_slice(swap::phases());
    out.extend_from_slice(drivers::phases());
    out.extend_from_slice(logd_sinks::phases());
    out.extend_from_slice(acpi::phases());
    out.extend_from_slice(vfsd::phases());
    out.extend_from_slice(unmount::phases());
    out.extend_from_slice(procmgr::init_reap());
    out.extend_from_slice(memmgr::identity());
    out
}
