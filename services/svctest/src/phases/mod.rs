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
//! 2. [`fs_opens`], [`fs_ipc`], [`fs_std`], [`fs_sessions`], [`fs_create_open`], and
//!    [`fs_faults`] near the end (but before [`pwrmgr`]). [`fs_opens`] comes before
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
//!    mounts it again and sets the cwd to it again. [`vfsd_caps`] after it,
//!    for the same reason.
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
//!     [`oom`], [`timed`], [`logd_restart`]): it holds the level at `CRITICAL` while it
//!     restores chunks from the restore headroom, which on a slow host outlasts
//!     oomd's grace. oomd then stops memhog, and svcmgr's restart of it, made
//!     while the level still reads `CRITICAL`, fails, which leaves memhog down
//!     with its endpoint still published.
//! 13. [`swapd`] after [`swap`], [`swap_client`] and [`swap_raw`]: it reuses
//!     their fixture and hog, and kills swapd, which no phase after it needs
//!     for a restore.
//! 14. [`swap_commit`] after [`swapd`]: its allowance is derived from the
//!     slots the swap service registered, and its write part needs a swap
//!     service that writes chunks to disk.
//! 15. [`fixtures`] right after [`startup`]: it reads the staged fixture
//!     set, which every later phase that drives a fixture consults, and fails
//!     the run before any of them when the image disagrees with it.
//! 16. The `crashd_oom_hold` phase of [`crashd`] after [`swap_commit`]: it
//!     fills memory until memmgr declines a fault crashd holds, so oomd stops
//!     the `memhog` fixture, whose restart while the level reads `CRITICAL`
//!     fails, as in item 12.
//! 17. [`memory_objects::early`] right after [`memmgr`]'s phases: it seals
//!     one contiguous grant of 32,768 pages, a run the pool holds at the
//!     default memory size only before the later phases leave its free
//!     memory in shorter runs.
//! 18. The [`CONCURRENT`] group next to each other, after [`recv_guard`]'s
//!     `recv_wedge` phase, which runs alone: its fixture reads memmgr's free
//!     pool around its failed grants, which the group's spawns would move.
//!
//! ### Concurrent group
//!
//! The phases [`CONCURRENT`] names run at once, each on a thread of its own,
//! and the runner joins them before the next phase starts
//! ([`crate::runner::run_all`]): each member's time is a wait on a bound that
//! is the behaviour under test, so the group takes the longest member's time
//! instead of their sum. A phase is a member only when it:
//!
//! - waits on a bound that is the behaviour under test, and asserts on no
//!   time that another member's load can stretch past its bound;
//! - touches only objects it creates (its endpoints, threads, children and
//!   queues), and asks a service nothing whose answer another member's
//!   requests change;
//! - reads no system-wide account (memmgr's pool, its levels or its `CSpace`,
//!   logd's history or its slots) and puts memory under no pressure.
//!
//! A member that fails while it runs in the group leaves it, and runs alone at
//! its place, until the failure is shown to be one it shows alone too. The
//! members lie next to each other in [`all`]'s order, which it checks.
//!
//! ### Selection
//!
//! A run whose recipe sets `SVCTEST_PHASES` (the `crash-endpoint` set's
//! staging, `svctest_fixtures::Set::phases`) makes the [`startup`] and
//! [`fixtures`] phases and, of the rest, only the phases that record names,
//! in this order; a name no phase has fails the run.

use crate::runner::Phase;

/// The concurrent group: the phases the runner runs at once (see the module
/// documentation).
pub(crate) const CONCURRENT: [&str; 3] = [
    "recv_wedge_thread",
    "procmgr_concurrent_spawn",
    "log_wedged_receiver",
];

/// Whether the phase `name` is a member of the [`CONCURRENT`] group.
pub(crate) fn concurrent(name: &str) -> bool
{
    CONCURRENT.contains(&name)
}

/// The shared program fixture the phases spawn in the mode its first argument
/// names (services/fixtures/program-modes/README.md).
pub(crate) const PROGRAM_MODES_PATH: &str = "/tests/fixtures/programs/program-modes";

pub mod acpi;
pub mod budget;
pub mod charge_node;
pub mod checkpoint;
pub mod console_whole_lines;
pub mod crash;
pub mod crashd;
pub mod critical_creates;
pub mod deadline;
pub mod debugger;
pub mod devmgr;
pub mod discard;
pub mod drivers;
pub mod entropyd;
pub mod exit_code;
pub mod fixtures;
pub mod fs_create_open;
pub mod fs_faults;
pub mod fs_ipc;
pub mod fs_opens;
pub mod fs_sessions;
pub mod fs_std;
pub mod heap_commit;
pub mod image_sharing;
pub mod layout;
pub mod log_client;
pub mod logd_restart;
pub mod logd_sinks;
pub mod memmgr;
pub mod memory_object_text;
pub mod memory_objects;
pub mod namespace;
pub mod no_receiver;
pub mod node_handle;
pub mod node_reclaim;
pub mod object_io;
pub mod oom;
pub mod pager;
pub mod pipes;
pub mod pipestress;
pub mod process_faults;
pub mod process_kill;
pub mod process_tree;
pub mod procmgr;
pub mod pwrmgr;
pub mod random;
pub mod recv_guard;
pub mod recv_pool;
pub mod restore;
pub mod serial_transmit;
pub mod sessiond;
pub mod shmem;
pub mod snapshot;
pub mod startup;
pub mod svcmgr;
pub mod swap;
pub mod swap_client;
pub mod swap_commit;
pub mod swap_raw;
pub mod swapd;
pub mod thread_exits;
pub mod threadchurn;
pub mod threading;
pub mod threadstack;
pub mod timed;
pub mod unmount;
pub mod verified_read;
pub mod vfsd;
pub mod vfsd_caps;

/// Ordered phase list. Order encodes cross-module dependencies, and the
/// recipe's selection, when it makes one, filters it (see the module-level
/// docstring above).
///
/// # Panics
///
/// When the selection names a phase the list does not hold, or the list does
/// not hold the members of the [`CONCURRENT`] group next to each other.
pub fn all() -> Vec<Phase>
{
    let mut out: Vec<Phase> = Vec::new();
    out.extend_from_slice(startup::main_startup());
    out.extend_from_slice(fixtures::phases());
    let always = out.len();
    out.extend_from_slice(&ordered());
    let members: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, p)| concurrent(p.name))
        .map(|(i, _)| i)
        .collect();
    assert!(
        members.len() == CONCURRENT.len()
            && members
                .windows(2)
                .all(|pair| matches!(pair, [a, b] if a.checked_add(1) == Some(*b))),
        "the concurrent group {CONCURRENT:?} lies at {members:?} of the phase list, not next to \
         each other"
    );
    let Ok(selection) = std::env::var(svctest_fixtures::PHASES_ENV)
    else
    {
        return out;
    };
    for name in selection.split(',')
    {
        assert!(
            out.iter().any(|p| p.name == name),
            "{}={selection}: no phase is named {name:?}",
            svctest_fixtures::PHASES_ENV
        );
    }
    out.into_iter()
        .enumerate()
        .filter(|(i, p)| *i < always || svctest_fixtures::selects(&selection, p.name))
        .map(|(_, p)| p)
        .collect()
}

/// The phases after the startup and fixture-check ones, in order.
fn ordered() -> Vec<Phase>
{
    let mut out: Vec<Phase> = Vec::new();
    out.extend_from_slice(memmgr::phases());
    out.extend_from_slice(memory_objects::early());
    out.extend_from_slice(layout::phases());
    out.extend_from_slice(threading::phases());
    out.extend_from_slice(procmgr::spawn_only());
    out.extend_from_slice(procmgr::logd_forward());
    out.extend_from_slice(process_faults::phases());
    out.extend_from_slice(exit_code::phases());
    out.extend_from_slice(crashd::faults_and_cores());
    out.extend_from_slice(deadline::phases());
    out.extend_from_slice(debugger::phases());
    out.extend_from_slice(threadchurn::phases());
    out.extend_from_slice(threadstack::phases());
    out.extend_from_slice(random::phases());
    out.extend_from_slice(entropyd::phases());
    out.extend_from_slice(recv_guard::phases());
    out.extend_from_slice(procmgr::concurrent_spawn());
    out.extend_from_slice(log_client::phases());
    out.extend_from_slice(recv_pool::phases());
    out.extend_from_slice(no_receiver::phases());
    out.extend_from_slice(devmgr::phases());
    out.extend_from_slice(pager::phases());
    out.extend_from_slice(budget::phases());
    out.extend_from_slice(node_handle::phases());
    out.extend_from_slice(charge_node::phases());
    out.extend_from_slice(heap_commit::phases());
    out.extend_from_slice(discard::phases());
    out.extend_from_slice(memory_objects::phases());
    out.extend_from_slice(object_io::phases());
    out.extend_from_slice(memory_object_text::phases());
    out.extend_from_slice(image_sharing::phases());
    out.extend_from_slice(snapshot::phases());
    out.extend_from_slice(checkpoint::phases());
    out.extend_from_slice(restore::phases());
    out.extend_from_slice(shmem::phases());
    out.extend_from_slice(pipes::phases());
    out.extend_from_slice(pipestress::phases());
    out.extend_from_slice(namespace::early());
    // fs_opens runs while /data's cache is still cold (its eviction phase's
    // CSpace case needs slots not yet provisioned) and writes the file the
    // slot-reuse phase of fs_ipc reads and removes.
    out.extend_from_slice(fs_opens::phases());
    out.extend_from_slice(fs_ipc::phases_pre_relative());
    out.extend_from_slice(fs_std::phases());
    out.extend_from_slice(fs_sessions::phases());
    out.extend_from_slice(fs_create_open::phases());
    out.extend_from_slice(fs_faults::phases());
    out.extend_from_slice(verified_read::phases());
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
    out.extend_from_slice(logd_restart::phases());
    out.extend_from_slice(swap::phases());
    out.extend_from_slice(node_reclaim::phases());
    out.extend_from_slice(swap_client::phases());
    out.extend_from_slice(swap_raw::phases());
    out.extend_from_slice(swapd::phases());
    out.extend_from_slice(swap_commit::phases());
    out.extend_from_slice(crashd::oom_hold());
    out.extend_from_slice(drivers::phases());
    // Before logd_sinks, whose stopped serial driver leaves logd's serial sink
    // stalled until its writer next completes a write: lines sent meanwhile
    // past the sink's queue are dropped by design, which the whole-lines
    // check would read as lines lost.
    out.extend_from_slice(console_whole_lines::phases());
    // Beside console_whole_lines, whose console check it shares; it writes
    // its lines to the serial driver itself, so logd_sinks's drops do not
    // touch them and it has no order of its own.
    out.extend_from_slice(serial_transmit::phases());
    out.extend_from_slice(logd_sinks::phases());
    out.extend_from_slice(acpi::phases());
    out.extend_from_slice(vfsd::phases());
    out.extend_from_slice(unmount::phases());
    out.extend_from_slice(vfsd_caps::phases());
    out.extend_from_slice(procmgr::init_reap());
    out.extend_from_slice(memmgr::identity());
    out
}
