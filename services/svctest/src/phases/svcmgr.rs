// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/svcmgr.rs

//! svcmgr service surface: the authority gates on its service endpoint, as
//! reached through svctest's per-process `service_registry_cap` and through
//! the SEND svcmgr publishes under `svcmgr`.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The svcmgr phases, in run order.
pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "svcmgr_handover_refused",
            run: svcmgr_handover_refused_phase,
        },
        Phase {
            name: "svcmgr_publish_gate",
            run: svcmgr_publish_gate_phase,
        },
        Phase {
            name: "svcmgr_published_send_badged",
            run: svcmgr_published_send_badged_phase,
        },
        Phase {
            name: "svcmgr_seed_only_names_refused",
            run: svcmgr_seed_only_names_refused_phase,
        },
        Phase {
            name: "svcmgr_second_seed_round",
            run: svcmgr_second_seed_round_phase,
        },
        Phase {
            name: "svcmgr_worker_fault_restart",
            run: svcmgr_worker_fault_restart_phase,
        },
        Phase {
            name: "svcmgr_stop_service",
            run: svcmgr_stop_service_phase,
        },
    ]
}

/// How long a phase waits for a fixture's provided name to be published, in
/// milliseconds: svcmgr may launch the fixture after svctest.
const FIXTURE_PUBLISH_WAIT_MS: u64 = 10_000;

/// The recipe that starts the fixture [`svcmgr_worker_fault_restart_phase`]
/// drives, when it is staged for this boot.
const WORKER_FAULT_RECIPE: &str = "/config/svcmgr/services/crasher-worker.svc";

/// End to end: a terminal fault of a thread other than the main thread of a
/// supervised service reaches svcmgr, which restarts the service under its
/// `restart = on-failure` policy. The `crasher` fixture's `worker-fault`
/// role (`rootfs/config/svcmgr/tests/crasher-worker.svc`) serves
/// `ipc::restart_probe_labels` on the name it provides: the phase reads the
/// instance's nonce, has a worker thread fault, and reads the nonce again
/// through the same SEND. procmgr's teardown stops the old instance's main
/// thread with no death post, so only svcmgr's address-space observer sees the
/// death; the second read is queued on the provided endpoint until the
/// restarted instance answers it with a new nonce. Were the death not routed,
/// no instance would receive again and the call would block until the run's
/// timeout.
///
/// The phase runs when the fixture's recipe is staged in
/// `/config/svcmgr/services/` and is skipped otherwise; once staged, the name
/// must be published within [`FIXTURE_PUBLISH_WAIT_MS`].
fn svcmgr_worker_fault_restart_phase(_caps: &Caps)
{
    use ipc::restart_probe_labels as probe;

    let phase = "svcmgr_worker_fault_restart";
    if !worker_fixture_staged(phase)
    {
        std::os::seraph::log!(
            "svcmgr_worker_fault_restart phase skipped: crasher-worker.svc not staged"
        );
        return;
    }
    let (_, ipc_buf) = registry_cap_and_buf(phase);
    let fixture = worker_fixture(phase);
    let nonce = |what: &str| probe_nonce(fixture, phase, what);

    let before = nonce("first PROBE_INSTANCE");
    let msg = ipc::IpcMessage::new(probe::PROBE_FAULT_WORKER);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(fixture, &msg, ipc_buf) }
        .expect("svcmgr_worker_fault_restart: PROBE_FAULT_WORKER call must return a reply");
    assert_eq!(
        reply.label,
        probe::SUCCESS,
        "svcmgr_worker_fault_restart: PROBE_FAULT_WORKER reply {:#x}",
        reply.label
    );
    let after = nonce("PROBE_INSTANCE after the worker fault");
    assert_ne!(
        before, after,
        "svcmgr_worker_fault_restart: the same instance answered after its worker faulted"
    );
    let _ = syscall::cap_delete(fixture);
    std::os::seraph::log!("svcmgr worker-fault-restart phase passed (restarted instance answered)");
}

/// Whether the worker-fault fixture's recipe is staged in
/// `/config/svcmgr/services/`; a stat error other than "not found" fails
/// `phase`.
fn worker_fixture_staged(phase: &str) -> bool
{
    recipe_staged(WORKER_FAULT_RECIPE, phase)
}

/// Whether the recipe at `path` is staged; a stat error other than "not
/// found" fails `phase`.
pub(super) fn recipe_staged(path: &str, phase: &str) -> bool
{
    match std::fs::metadata(path)
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => panic!("{phase}: stat {path}: {e:?}"),
    }
}

/// A SEND on the endpoint the worker-fault fixture provides
/// (`ipc::restart_probe_labels::NAME`), as [`provided_endpoint`] resolves it.
fn worker_fixture(phase: &str) -> u64
{
    provided_endpoint(ipc::restart_probe_labels::NAME, phase)
}

/// A SEND on the endpoint a fixture provides under `name`, resolved through
/// `QUERY_ENDPOINT` once it is published, within
/// [`FIXTURE_PUBLISH_WAIT_MS`]. The endpoint outlives each instance, so
/// the SEND reaches every restart.
pub(super) fn provided_endpoint(name: &[u8], phase: &str) -> u64
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf(phase);
    let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16);
    let mut waited_ms = 0;
    let fixture = loop
    {
        let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
            .expect("svcmgr QUERY_ENDPOINT ipc_call must return a reply");
        if reply.label == ipc::svcmgr_errors::SUCCESS
        {
            break reply.caps().first().copied().unwrap_or(0);
        }
        assert!(
            waited_ms < FIXTURE_PUBLISH_WAIT_MS,
            "{phase}: {} not published within {FIXTURE_PUBLISH_WAIT_MS} ms, last reply {:#x}",
            String::from_utf8_lossy(name),
            reply.label
        );
        let _ = syscall::thread_sleep(50);
        waited_ms = waited_ms.saturating_add(50);
    };
    assert_ne!(fixture, 0, "{phase}: QUERY_ENDPOINT returned no cap");
    fixture
}

/// The nonce of the worker-fault fixture's running instance, read through
/// `fixture` with `PROBE_INSTANCE`; `what` names the read in a failure.
fn probe_nonce(fixture: u64, phase: &str, what: &str) -> u64
{
    use ipc::restart_probe_labels as probe;
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::new(probe::PROBE_INSTANCE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(fixture, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: {what} call failed: {e:?}"));
    assert_eq!(
        reply.label,
        probe::SUCCESS,
        "{phase}: {what} reply {:#x}",
        reply.label
    );
    reply.word(0)
}

/// One entry of a `LIST_CANDIDATES` walk: the candidate's name, its key,
/// its rank and the pages its subtree holds.
#[derive(Debug)]
pub(super) struct Listed
{
    pub(super) name: String,
    pub(super) key: u64,
    pub(super) rank: u64,
    pub(super) pages: u64,
}

/// The recipe that starts the stop-source fixture, when it is staged for this
/// boot.
pub(super) const STOPSRC_RECIPE: &str = "/config/svcmgr/services/stopsrc.svc";

/// The name procmgr lists `stopsrc`'s job under: the first word of its argv,
/// the path the fixture creates it from. The fixture's own instance, which
/// svcmgr creates with no argv, is listed with an empty name.
const STOPSRC_PATH: &[u8] = b"/tests/stopsrc";

/// The pages of the job [`check_source_contained`] has `stopsrc` start: one,
/// since only its process is looked for.
const CONTAIN_JOB_PAGES: u64 = 1;

/// How long [`check_source_contained`] waits, once `stopsrc`'s next instance
/// answers, for procmgr to stop listing the job of the instance that exited.
/// A test wait bound.
const CONTAIN_WAIT_MS: u64 = 2000;

/// Call `label` with `data[0] = word` through `cap`, delete any cap the reply
/// carries, and return the reply label; `what` names the call in a failure.
fn call_label(cap: u64, label: u64, word: u64, what: &str) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(label).word(0, word).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed: {e:?}"));
    for &held in reply.caps()
    {
        let _ = syscall::cap_delete(held);
    }
    reply.label
}

/// `STOP_CANDIDATE` of `key` through `cap`: the reply label. Allocates
/// nothing.
pub(super) fn stop_candidate(cap: u64, key: u64) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(ipc::stop_labels::STOP_CANDIDATE)
        .word(0, key)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
        .expect("STOP_CANDIDATE ipc_call must return a reply")
        .label
}

/// The whole `LIST_CANDIDATES` walk of the source `cap` reaches, page by
/// page until a short page. Fails `phase` on a reply other than `SUCCESS`, a
/// page that does not decode, or a cursor that does not advance.
pub(super) fn list_candidates(cap: u64, phase: &str) -> Vec<Listed>
{
    use ipc::stop_labels::{LIST_CANDIDATES, LIST_CANDIDATES_PAGE, SUCCESS, unpack_candidate};
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut listed = Vec::new();
    let mut cursor = 0;
    loop
    {
        let msg = ipc::IpcMessage::builder(LIST_CANDIDATES)
            .word(0, cursor)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
            .expect("LIST_CANDIDATES ipc_call must return a reply");
        assert_eq!(
            reply.label, SUCCESS,
            "{phase}: LIST_CANDIDATES reply {:#x}",
            reply.label
        );
        let count = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
        assert!(
            count <= LIST_CANDIDATES_PAGE,
            "{phase}: LIST_CANDIDATES page of {count} entries"
        );
        for index in 0..count
        {
            let entry = unpack_candidate(reply.words(), index).unwrap_or_else(|| {
                panic!("{phase}: LIST_CANDIDATES entry {index} does not decode")
            });
            let name = entry.name.get(..entry.len).unwrap_or_default();
            listed.push(Listed {
                name: String::from_utf8_lossy(name).into_owned(),
                key: entry.key,
                rank: entry.rank,
                pages: entry.pages,
            });
        }
        if count < LIST_CANDIDATES_PAGE
        {
            return listed;
        }
        assert!(
            reply.word(1) > cursor,
            "{phase}: LIST_CANDIDATES cursor did not advance"
        );
        cursor = reply.word(1);
    }
}

/// The whole `LIST_STOP_SOURCES` walk through svcmgr's stop authority
/// `cap`: each source's name, its class, and the stop-badged SEND the reply
/// carried for it, which the caller deletes. Fails `phase` on a reply other
/// than `SUCCESS`, an entry that does not decode or has no cap, or a cursor
/// that does not advance.
pub(super) fn list_stop_sources(cap: u64, phase: &str) -> Vec<(String, u64, u64)>
{
    use ipc::svcmgr_labels::{LIST_STOP_SOURCES, LIST_STOP_SOURCES_PAGE, unpack_stop_source};
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut listed = Vec::new();
    let mut cursor = 0;
    loop
    {
        let msg = ipc::IpcMessage::builder(LIST_STOP_SOURCES)
            .word(0, cursor)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
            .expect("LIST_STOP_SOURCES ipc_call must return a reply");
        assert_eq!(
            reply.label,
            ipc::svcmgr_errors::SUCCESS,
            "{phase}: LIST_STOP_SOURCES reply {:#x}",
            reply.label
        );
        let count = usize::try_from(reply.word(0)).unwrap_or(usize::MAX);
        assert!(
            count <= LIST_STOP_SOURCES_PAGE && reply.caps().len() == count,
            "{phase}: LIST_STOP_SOURCES page of {count} entries and {} caps",
            reply.caps().len()
        );
        for (index, &send) in reply.caps().iter().enumerate()
        {
            let (class, name, len) =
                unpack_stop_source(reply.words(), index).unwrap_or_else(|| {
                    panic!("{phase}: LIST_STOP_SOURCES entry {index} does not decode")
                });
            assert_ne!(
                send, 0,
                "{phase}: LIST_STOP_SOURCES entry {index} has no cap"
            );
            let name = name.get(..len).unwrap_or_default();
            listed.push((String::from_utf8_lossy(name).into_owned(), class, send));
        }
        if count < LIST_STOP_SOURCES_PAGE
        {
            return listed;
        }
        assert!(
            reply.word(1) > cursor,
            "{phase}: LIST_STOP_SOURCES cursor did not advance"
        );
        cursor = reply.word(1);
    }
}

/// The slots below which [`svcmgr_stop_service_phase`] tries the keys of
/// services svcmgr does not list; svcmgr's table holds fewer at this boot.
const UNLISTED_SLOTS: u64 = 32;

/// The key svcmgr gives the service in table `slot` at `instance`
/// (`svcmgr_defs::DeathTag`'s correlator): opaque to a stop-authority
/// holder, and built here only to name keys svcmgr must refuse.
fn service_key(slot: u64, instance: u64) -> u64
{
    (instance << 32) | slot
}

/// The stop sources of [`svcmgr_stop_service_phase`]: `LIST_STOP_SOURCES`
/// through svcmgr's stop authority `stop_cap` lists `stopsrc` alone, with
/// the program class, when its recipe is staged, and nothing otherwise; the
/// SEND it carries reaches the fixture's stop labels, and the fixture's own
/// `:deny` SEND does not.
fn check_stop_sources(stop_cap: u64, phase: &str)
{
    use ipc::stop_labels::{
        CLASS_PROGRAM, LIST_CANDIDATES, NO_CANDIDATE, STOP_CANDIDATE, SUCCESS, UNAUTHORIZED,
    };
    let sources = list_stop_sources(stop_cap, phase);
    let stopsrc = recipe_staged(STOPSRC_RECIPE, phase);
    let shown: Vec<(&str, u64)> = sources.iter().map(|(n, c, _)| (n.as_str(), *c)).collect();
    let want: &[(&str, u64)] = if stopsrc
    {
        &[("stopsrc", CLASS_PROGRAM)]
    }
    else
    {
        &[]
    };
    assert_eq!(
        shown, want,
        "{phase}: LIST_STOP_SOURCES must list the staged stop_source fixtures alone"
    );
    for &(_, _, send) in &sources
    {
        let label = call_label(send, LIST_CANDIDATES, 0, phase);
        assert_eq!(
            label, SUCCESS,
            "{phase}: LIST_CANDIDATES through stopsrc's stop SEND replied {label:#x}"
        );
        let label = stop_candidate(send, u64::MAX);
        assert_eq!(
            label, NO_CANDIDATE,
            "{phase}: STOP_CANDIDATE of a key stopsrc never gave replied {label:#x}"
        );
        let _ = syscall::cap_delete(send);
    }
    if stopsrc
    {
        let deny = provided_endpoint(ipc::stopsrc_labels::NAME, phase);
        for (label, what) in [
            (STOP_CANDIDATE, "STOP_CANDIDATE"),
            (LIST_CANDIDATES, "LIST_CANDIDATES"),
        ]
        {
            let got = call_label(deny, label, 0, phase);
            assert_eq!(
                got, UNAUTHORIZED,
                "{phase}: {what} through stopsrc's :deny SEND replied {got:#x}"
            );
        }
        let _ = syscall::cap_delete(deny);
    }
}

/// The containment of a stop source (services/svcmgr/docs/service-definitions.md
/// § `stop_source`): svcmgr creates `stopsrc` contained, so the job an
/// instance started ends with that instance. Through the debug authority
/// `authority`, `LIST_PROCESSES` lists one new process named
/// [`STOPSRC_PATH`], the job, once `START_JOB` has the instance start one;
/// once the instance has exited (`EXIT`, which leaves the job running) and
/// its restarted successor answers, the job's badge leaves the list within
/// [`CONTAIN_WAIT_MS`]. Created uncontained, the job would be re-parented
/// and listed on.
fn check_source_contained(authority: u64, phase: &str)
{
    use super::crash::badges_named;
    use super::oom::src_call;
    use ipc::stopsrc_labels as src;
    assert_ne!(
        authority, 0,
        "{phase}: no debug-authority cap in slot 15 (debug_authority = yes)"
    );
    let fixture = provided_endpoint(src::NAME, phase);
    let before = badges_named(authority, STOPSRC_PATH);
    let (first, _, _) = src_call(fixture, src::PROBE, 0, phase, "stopsrc PROBE");
    let _ = src_call(
        fixture,
        src::START_JOB,
        CONTAIN_JOB_PAGES,
        phase,
        "stopsrc START_JOB",
    );
    let jobs: Vec<u64> = badges_named(authority, STOPSRC_PATH)
        .into_iter()
        .filter(|badge| !before.contains(badge))
        .collect();
    let [job] = jobs[..]
    else
    {
        panic!("{phase}: LIST_PROCESSES lists {jobs:#x?} as stopsrc's new job");
    };
    let _ = src_call(fixture, src::EXIT, 0, phase, "stopsrc EXIT");
    let (next, _, _) = src_call(fixture, src::PROBE, 0, phase, "stopsrc PROBE after EXIT");
    assert_ne!(next, first, "{phase}: stopsrc did not restart");
    let start = std::time::Instant::now();
    while badges_named(authority, STOPSRC_PATH).contains(&job)
    {
        assert!(
            start.elapsed() < std::time::Duration::from_millis(CONTAIN_WAIT_MS),
            "{phase}: stopsrc's job {job:#x} outlived the instance that started it"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = syscall::cap_delete(fixture);
}

/// End to end: the stop authority (services/svcmgr/docs/ipc-interface.md
/// § Stop authority). `STOP_CANDIDATE`, `LIST_CANDIDATES` and
/// `LIST_STOP_SOURCES` through the per-process SEND, which carries no verb
/// bit, reply `UNAUTHORIZED`.
///
/// Through the `STOP_AUTHORITY` SEND svctest's recipe (`stop_authority =
/// yes`) delivers after the debug-authority slot, the whole
/// `LIST_CANDIDATES` walk lists the staged fixtures whose recipes set
/// `oom_stop = yes` (`crasher-worker`, and `memhog`, which the `oom` phase
/// drives), each with a non-zero usage and the service rank, and no other
/// service, since no other recipe of the boot sets the key. svcmgr refuses
/// with `NO_CANDIDATE` the first instance's key of every slot below
/// [`UNLISTED_SLOTS`] it does not list: those slots hold the services the
/// eligibility rule refuses (svctest itself, `restart = never`; the ones init
/// started; logd, critical; pwrmgr and `stopsrc`, core roles; timed, no
/// `oom_stop`), and past the table, none. The rule's every row is host-tested
/// in `svcmgr-defs` (`svcmgr_defs::stop`).
///
/// `LIST_STOP_SOURCES` lists the `stopsrc` fixture alone, with the program
/// class, when its recipe is staged, and nothing otherwise. The SEND it
/// carries reaches the fixture's stop labels: its list replies `SUCCESS`,
/// and a stop of a key it never gave replies `NO_CANDIDATE`. The fixture's
/// own `:deny` SEND, which any process can query, gets `UNAUTHORIZED` for
/// both, and the job an instance of it started ends with that instance
/// ([`check_source_contained`]).
///
/// With `crasher-worker` staged, `STOP_CANDIDATE` of its listed key replies
/// `SUCCESS`, and the restart probe then answers with a new instance's nonce:
/// svcmgr destroyed the instance and its `restart = on_failure` policy
/// restarted it after the `EXIT_KILLED` death. The same key then replies
/// `NO_CANDIDATE`: it named the instance that is gone.
fn svcmgr_stop_service_phase(caps: &Caps)
{
    use ipc::stop_labels::{
        LIST_CANDIDATES, NO_CANDIDATE, RANK_SERVICE, STOP_CANDIDATE, SUCCESS, UNAUTHORIZED,
    };
    let phase = "svcmgr_stop_service";
    let (registry_cap, _) = registry_cap_and_buf(phase);
    let stop_cap = caps.stop_authority;
    assert_ne!(
        stop_cap, 0,
        "{phase}: no stop-authority cap in slot 16 (stop_authority = yes)"
    );

    for (label, want, what) in [
        (STOP_CANDIDATE, UNAUTHORIZED, "STOP_CANDIDATE"),
        (LIST_CANDIDATES, UNAUTHORIZED, "LIST_CANDIDATES"),
        (
            ipc::svcmgr_labels::LIST_STOP_SOURCES,
            ipc::svcmgr_errors::UNAUTHORIZED,
            "LIST_STOP_SOURCES",
        ),
    ]
    {
        let got = call_label(registry_cap, label, 0, phase);
        assert_eq!(
            got, want,
            "{phase}: {what} through the per-process SEND replied {got:#x}"
        );
    }

    let staged = worker_fixture_staged(phase);
    let mut expected: Vec<&str> = Vec::new();
    if staged
    {
        expected.push("crasher-worker");
    }
    if recipe_staged(super::oom::MEMHOG_RECIPE, phase)
    {
        expected.push("memhog");
    }
    expected.sort_unstable();
    let listed = list_candidates(stop_cap, phase);
    let mut names: Vec<&str> = listed.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    assert!(
        names == expected && listed.iter().all(|c| c.pages > 0 && c.rank == RANK_SERVICE),
        "{phase}: LIST_CANDIDATES must list the staged oom_stop fixtures {expected:?} alone, \
         each with its usage and the service rank: {listed:?}"
    );
    let listed_slots: Vec<u64> = listed.iter().map(|c| c.key & 0xFFFF_FFFF).collect();
    for slot in (0..UNLISTED_SLOTS).filter(|slot| !listed_slots.contains(slot))
    {
        let label = stop_candidate(stop_cap, service_key(slot, 0));
        assert_eq!(
            label, NO_CANDIDATE,
            "{phase}: STOP_CANDIDATE of unlisted slot {slot} replied {label:#x}"
        );
    }

    check_stop_sources(stop_cap, phase);
    if recipe_staged(STOPSRC_RECIPE, phase)
    {
        check_source_contained(caps.debug_authority, phase);
    }
    if !staged
    {
        std::os::seraph::log!(
            "svcmgr stop-service phase passed (gates and refusals; crasher-worker.svc not staged)"
        );
        return;
    }

    let key = listed
        .iter()
        .find(|c| c.name == "crasher-worker")
        .map_or(0, |c| c.key);
    let fixture = worker_fixture(phase);
    let before = probe_nonce(fixture, phase, "PROBE_INSTANCE before the stop");
    let label = stop_candidate(stop_cap, key);
    assert_eq!(
        label, SUCCESS,
        "{phase}: STOP_CANDIDATE(crasher-worker) replied {label:#x}"
    );
    let after = probe_nonce(fixture, phase, "PROBE_INSTANCE after the stop");
    assert_ne!(
        before, after,
        "{phase}: the stopped instance still answered"
    );
    let label = stop_candidate(stop_cap, key);
    assert_eq!(
        label, NO_CANDIDATE,
        "{phase}: STOP_CANDIDATE of the stopped instance's key replied {label:#x}"
    );
    let _ = syscall::cap_delete(fixture);
    std::os::seraph::log!(
        "svcmgr stop-service phase passed (gates, refusals, sources, crasher-worker stopped and \
         restarted)"
    );
}

/// The recipe's fifth and sixth seeds (`vfsd.mount`, `vfsd.deny`) fill
/// slots 4 and 5, which svcmgr serves in a second bootstrap round, since one
/// round carries at most `MSG_CAP_SLOTS_MAX` caps. An empty slot there means
/// the seed list lost its second round (or the name did not resolve).
fn svcmgr_second_seed_round_phase(caps: &Caps)
{
    for (slot, cap, shown) in [
        (4, caps.vfsd_mount, "vfsd.mount"),
        (5, caps.vfsd_deny, "vfsd.deny"),
    ]
    {
        assert_ne!(
            cap, 0,
            "svcmgr_second_seed_round: slot {slot} ({shown}) empty: second seed round lost or \
             name unresolved"
        );
    }
    std::os::seraph::log!("svcmgr second-seed-round phase passed (slots 4 and 5 present)");
}

/// The registry SEND procmgr installed in svctest's `ProcessInfo`, and the
/// IPC buffer to call it with.
fn registry_cap_and_buf(phase: &str) -> (u64, *mut u64)
{
    let info = startup_info();
    let registry_cap = info.service_registry_cap;
    assert_ne!(
        registry_cap, 0,
        "{phase}: no service_registry_cap in ProcessInfo"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    (registry_cap, ipc_buf)
}

/// End to end: a `HANDOVER_COMPLETE` sent after init's handover through the
/// per-process SEND must be refused. Were it honoured, svcmgr would re-run
/// reconciliation and launch a second instance of every defined service.
/// svctest always runs after the handover, so the badge test and the
/// once-only rule both refuse this call and the phase cannot tell them apart;
/// each is host-tested on its own in `svcmgr-defs`
/// (`handover_needs_the_authority_bit`, `handover_is_honoured_only_once`).
fn svcmgr_handover_refused_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_handover_refused");
    let msg = ipc::IpcMessage::new(ipc::svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr HANDOVER_COMPLETE ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "svcmgr HANDOVER_COMPLETE after the handover must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("svcmgr handover-refused phase passed (UNAUTHORIZED reply)");
}

/// `PUBLISH_ENDPOINT` through the per-process SEND must fail the
/// `PUBLISH_AUTHORITY` gate. svcmgr checks the badge before the attached
/// cap, so a request with a valid name and no cap replies `UNAUTHORIZED`
/// only when the process badge lacks the verb-bit; a badge carrying it
/// would reach the cap check and reply `INSUFFICIENT_CAPS`.
fn svcmgr_publish_gate_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_publish_gate");
    let name = b"svctest.forged";
    let label = ipc::svcmgr_labels::PUBLISH_ENDPOINT | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr PUBLISH_ENDPOINT ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "svcmgr PUBLISH_ENDPOINT through the per-process SEND must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("svcmgr publish-gate phase passed (UNAUTHORIZED reply)");
}

/// The SEND svcmgr publishes under `svcmgr` must be badged and lack
/// `PUBLISH_AUTHORITY`. Already badged, it cannot be re-badged, so a
/// consumer cannot mint `HANDOVER_AUTHORITY` from it: the kernel refuses a
/// re-badge of a badged source with `InvalidArgument`. Lacking
/// `PUBLISH_AUTHORITY`, it fails the publish gate: a nameful, capless
/// `PUBLISH_ENDPOINT` through it replies `UNAUTHORIZED`, where the bit would
/// reach the cap check. Whether the badge carries `HANDOVER_AUTHORITY` is
/// not observable after the handover; a compile-time assertion beside
/// `ipc::svcmgr_labels::PUBLISHED_SEND_BADGE` keeps every verb-bit out of it.
fn svcmgr_published_send_badged_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_published_send_badged");
    let name = ipc::published_names::SVCMGR;
    let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr QUERY_ENDPOINT ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::SUCCESS,
        "svcmgr QUERY_ENDPOINT(svcmgr) must resolve (got {:#x})",
        reply.label
    );
    let published = reply.caps().first().copied().unwrap_or(0);
    assert_ne!(
        published, 0,
        "svcmgr QUERY_ENDPOINT(svcmgr) returned no cap"
    );

    let rebadged = syscall::cap_derive_badge(
        published,
        syscall::RIGHTS_EP_SEND,
        ipc::svcmgr_labels::HANDOVER_AUTHORITY,
    );
    if let Ok(forged) = rebadged
    {
        let _ = syscall::cap_delete(forged);
    }

    let forged_name = b"svctest.forged";
    let publish_label = ipc::svcmgr_labels::PUBLISH_ENDPOINT | ((forged_name.len() as u64) << 16);
    let publish = ipc::IpcMessage::builder(publish_label)
        .bytes(0, forged_name)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let publish_reply = unsafe { ipc::ipc_call(published, &publish, ipc_buf) };
    let _ = syscall::cap_delete(published);

    assert_eq!(
        rebadged,
        Err(syscall_abi::SyscallError::InvalidArgument as i64),
        "re-badging the published svcmgr SEND must fail as already badged"
    );
    let publish_label = publish_reply
        .expect("svcmgr PUBLISH_ENDPOINT ipc_call must return a reply")
        .label;
    assert_eq!(
        publish_label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "PUBLISH_ENDPOINT through the published svcmgr SEND must reply UNAUTHORIZED (got {publish_label:#x})"
    );
    std::os::seraph::log!("svcmgr published-send phase passed (badged, no PUBLISH_AUTHORITY)");
}

/// The names `svcmgr_seed_only_names_refused_phase` checks `QUERY_ENDPOINT`
/// refuses: every seed-only name.
const SEED_ONLY_NAMES: &[&[u8]] = &[
    ipc::published_names::ROOTFS_ROOT,
    ipc::published_names::PWRMGR_SHUTDOWN,
    ipc::published_names::ACPID_POWER,
    ipc::published_names::DEVMGR_REGISTRY,
    ipc::published_names::DEVMGR_SHUTDOWN,
    ipc::published_names::DEVMGR_BIND,
    ipc::published_names::DEVMGR_ACPI,
    ipc::published_names::VFSD_MOUNT,
    ipc::published_names::VFSD_DENY,
    ipc::published_names::VFSD_SWAP,
    ipc::published_names::LOGD_QUERY,
    b"devmgr.class.block",
    b"devmgr.class.serial",
    b"devmgr.class.framebuffer",
    b"devmgr.class.rtc",
    b"devmgr.class.input",
    b"devmgr.class.debug-port",
    b"devmgr.class.test-dma",
    b"devmgr.class.test-fault",
    b"devmgr.class.serial-deny",
    b"devmgr.class.input-deny",
    b"devmgr.class.framebuffer-deny",
];

/// The public names `svcmgr_seed_only_names_refused_phase` checks
/// `QUERY_ENDPOINT` resolves.
const PUBLIC_NAMES: &[&[u8]] = &[
    ipc::published_names::SVCMGR,
    ipc::published_names::PWRMGR_DENY,
    ipc::published_names::ACPID_DENY,
];

/// `QUERY_ENDPOINT` through the per-process SEND refuses every seed-only
/// name with `UNKNOWN_NAME` and no cap, and resolves the public ones with a
/// cap. svctest's own non-zero seeds show fifteen of the refused names are
/// published; `devmgr.shutdown`, which only pwrmgr seeds, and `devmgr.acpi`,
/// which only acpid seeds, are published by the same loop as
/// `devmgr.registry` and `devmgr.bind`, `acpid.power`,
/// which only pwrmgr seeds, by the same `provides` loop as `acpid.deny`,
/// which resolves, and the other
/// `devmgr.class.*` names by the same class loop as `devmgr.class.serial` and
/// `devmgr.class.input`, among them `devmgr.class.debug-port`, which only the
/// `debug-echo` fixture and `gdbstub` seed. A queryable seed-only name would
/// hand its authority to every process, and `devmgr.bind`, whose seeds keep
/// `GRANT`, its `GRANT` too.
fn svcmgr_seed_only_names_refused_phase(caps: &Caps)
{
    for (cap, shown) in [
        (caps.root_fs, "rootfs.root"),
        (caps.pwrmgr_auth, "pwrmgr.shutdown"),
        (caps.devmgr_registry, "devmgr.registry"),
        (caps.devmgr_bind, "devmgr.bind"),
        (caps.vfsd_mount, "vfsd.mount"),
        (caps.vfsd_deny, "vfsd.deny"),
        (caps.logd_query, "logd.query"),
        (caps.serial_class, "devmgr.class.serial"),
        (caps.input_class, "devmgr.class.input"),
        (caps.test_dma_class, "devmgr.class.test-dma"),
        (caps.test_fault_class, "devmgr.class.test-fault"),
        (caps.serial_deny_class, "devmgr.class.serial-deny"),
        (caps.input_deny_class, "devmgr.class.input-deny"),
        (caps.framebuffer_deny_class, "devmgr.class.framebuffer-deny"),
        (caps.vfsd_swap, "vfsd.swap"),
    ]
    {
        assert_ne!(cap, 0, "svcmgr_seed_only_names_refused: no {shown} seed");
    }
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_seed_only_names_refused");
    let query = |name: &[u8]| {
        let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16);
        let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
            .expect("svcmgr QUERY_ENDPOINT ipc_call must return a reply")
    };
    for &name in SEED_ONLY_NAMES
    {
        let reply = query(name);
        let shown = core::str::from_utf8(name).unwrap_or("?");
        assert_eq!(
            reply.label,
            ipc::svcmgr_errors::UNKNOWN_NAME,
            "svcmgr QUERY_ENDPOINT({shown}) must reply UNKNOWN_NAME (got {:#x})",
            reply.label
        );
        assert!(
            reply.caps().is_empty(),
            "svcmgr QUERY_ENDPOINT({shown}) refusal must carry no cap"
        );
    }
    for &name in PUBLIC_NAMES
    {
        let reply = query(name);
        let shown = core::str::from_utf8(name).unwrap_or("?");
        assert_eq!(
            reply.label,
            ipc::svcmgr_errors::SUCCESS,
            "svcmgr QUERY_ENDPOINT({shown}) must resolve (got {:#x})",
            reply.label
        );
        assert_eq!(
            reply.caps().len(),
            1,
            "svcmgr QUERY_ENDPOINT({shown}) must carry one cap"
        );
        for &cap in reply.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    std::os::seraph::log!(
        "svcmgr seed-only phase passed ({} refused, {} public resolved)",
        SEED_ONLY_NAMES.len(),
        PUBLIC_NAMES.len()
    );
}
