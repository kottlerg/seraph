// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/oom.rs

//! The out-of-memory policy end to end (services/oomd/docs/operation.md): the
//! `memhog` fixture fills memmgr's pool down to its growth floor, and oomd
//! stops it once the level has read `CRITICAL` for its grace, or, with
//! `OOMD_STOP=no`, nothing stops it. With the `stopsrc` fixture staged, oomd
//! first stops the job that stop source lists, since the program class is
//! stopped before the service class. svctest opens an operator session whose
//! leader runs a job larger than `stopsrc`'s, and oomd stops that job first,
//! then `stopsrc`'s, then the sessions, then the fixture
//! (docs/session-supervision.md). oomd and sessiond are of the default service
//! set, which svctest requires staged ([`super::fixtures`]).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ipc::memhog_labels as hog;
use ipc::stopsrc_labels as src;
use std::os::seraph::MemoryPressure;
use svctest_fixtures::Fixture;

use super::fixtures;
use super::sessiond::CRASHME_PATH;
use crate::bootstrap::Caps;
use crate::runner::Phase;

/// oomd's recipe, of the default service set, which svctest requires staged
/// ([`super::fixtures`]).
pub(super) const OOMD_RECIPE: &str = "/config/svcmgr/services/oomd.svc";

/// crashd's recipe, when the image starts crashd.
const CRASHD_RECIPE: &str = svctest_fixtures::CRASHD_STAGED_PATH;

/// How long the phase waits for the level to read `NORMAL`: before the
/// fill, for what earlier phases left, and after it, for oomd's grace, its
/// stop (with `stopsrc`'s job stopped first, a cooldown later), and
/// memmgr's reclaim of the fixture's memory. A test wait bound.
const NORMAL_WAIT: Duration = Duration::from_secs(60);

/// How long the phase waits for oomd's and crashd's lines to reach logd's
/// history once the level has fallen. A test wait bound.
const LOG_WAIT: Duration = Duration::from_secs(10);

/// How often the phase reads the level, or logd's history, while it waits.
const LEVEL_POLL: Duration = Duration::from_millis(20);

/// How long past oomd's grace and cooldown the no-stop case watches the level
/// stay `CRITICAL` with the fixture running.
const NO_STOP_MARGIN_MS: u64 = 2000;

/// How long the phase waits for the `oom-touch` child to exit once the
/// level has fallen. A test wait bound.
const CHILD_WAIT: Duration = Duration::from_secs(30);

/// Bytes of stack the phase touches before the fill, below its frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

/// The prefix of oomd's line for a stop of the fixture.
const STOP_LINE: &[u8] = b"stopped memhog: ";

/// The prefix of oomd's line for a stop of `stopsrc`'s job.
const JOB_STOP_LINE: &[u8] = b"stopped stopsrc-job: ";

/// The pages of the job the stop case has `stopsrc` start: few, so its stop
/// leaves the level `CRITICAL` while memhog tops its fill up.
const JOB_PAGES: u64 = 64;

/// The prefix of oomd's line for a stop of the session's job.
const HOLD_STOP_LINE: &[u8] = b"stopped /tests/fixtures/programs/crashme: ";

/// The prefix of oomd's line for a stop of a session.
const SESSION_STOP_LINE: &[u8] = b"stopped session ";

/// The pages of the job the stop case has its session's leader start: more
/// than [`JOB_PAGES`] by far, so oomd stops it before `stopsrc`'s.
const HOLD_PAGES: u64 = 512;

/// The prefix of oomd's line naming the candidate it would stop. In advice mode
/// nothing is stopped, so each line names the first of oomd's stop order: the
/// operator session while one is open.
const ADVICE_LINE: &[u8] = b"would stop ";

/// The part of crashd's line for a fault it holds.
const HELD_LINE: &[u8] = b"held: memory critical";

/// The part of crashd's line for a held fault it resumed.
const RESUMED_LINE: &[u8] = b"resumed after";

/// The pages of the demand region the `oom-touch` child writes, one after
/// another: twice the largest program the phase starts ([`HOLD_PAGES`]). A stop
/// frees its candidate's pages above the growth floor, where a process outside
/// the reserve is granted them until memhog's next top-up (`mem_fill::TICK_MS`)
/// takes them back, and the level stays `CRITICAL` meanwhile. The writes spend
/// what the stop before them left there, so a later write is the one memmgr
/// declines and crashd holds, wherever the first lands against the tick.
const TOUCH_PAGES: u64 = 2 * HOLD_PAGES;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "oom_policy",
        run: oom_policy_phase,
    }]
}

/// What oomd's recipe sets, as oomd reads it (`oomd_policy`).
fn oomd_config(phase: &str) -> oomd_policy::Config
{
    let recipe = recipe_text(OOMD_RECIPE, phase)
        .unwrap_or_else(|| panic!("{phase}: {OOMD_RECIPE} is not staged"));
    let grace = oomd_policy::parse_ms(
        env_value(&recipe, "OOMD_GRACE_MS"),
        oomd_policy::GRACE_DEFAULT_MS,
    );
    let cooldown = oomd_policy::parse_ms(
        env_value(&recipe, "OOMD_COOLDOWN_MS"),
        oomd_policy::COOLDOWN_DEFAULT_MS,
    );
    oomd_policy::Config {
        grace_ms: grace.value,
        cooldown_ms: cooldown.value,
        mode: oomd_policy::parse_stop(env_value(&recipe, "OOMD_STOP")).value,
    }
}

/// crashd's stall, when crashd runs and holds a fault declined for want of
/// memory: its recipe is staged and sets a non-zero `CRASHD_OOM_STALL_MS`.
pub(super) fn crashd_stall(phase: &str) -> Option<u64>
{
    recipe_text(CRASHD_RECIPE, phase).and_then(|recipe| {
        env_value(&recipe, "CRASHD_OOM_STALL_MS")
            .and_then(|ms| ms.parse::<u64>().ok())
            .filter(|&ms| ms != 0)
    })
}

/// The text of the recipe at `path`, read as svcmgr reads it: through
/// procmgr's verified read in the configuration role, so the body is the
/// signed recipe less its trailer (docs/signing.md § Configuration); `None`
/// when it is not staged.
fn recipe_text(path: &str, phase: &str) -> Option<String>
{
    use std::os::seraph::{VerifiedRole, namespace_lookup_file, read_verified, root_dir_cap};
    super::svcmgr::recipe_staged(path, phase).then(|| {
        let (cap, size) = namespace_lookup_file(root_dir_cap(), path)
            .unwrap_or_else(|e| panic!("{phase}: look up {path}: {e:?}"));
        let verified = read_verified(cap, size, path, VerifiedRole::Configuration)
            .unwrap_or_else(|e| panic!("{phase}: verified read of {path}: {e:?}"));
        String::from_utf8(verified.bytes().to_vec())
            .unwrap_or_else(|e| panic!("{phase}: {path} is not UTF-8: {e:?}"))
    })
}

/// The value the recipe text `recipe`'s `env` line gives `key`.
fn env_value<'a>(recipe: &'a str, key: &str) -> Option<&'a str>
{
    recipe
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| name.trim() == "env")
        .flat_map(|(_, value)| value.split_whitespace())
        .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
}

/// The out-of-memory policy, with the `memhog` fixture staged; the phase
/// skips when the staged set does not declare it, which leaves no service
/// oomd may stop.
///
/// With oomd's `OOMD_STOP` not `no` (the stop case): the
/// fixture fills the pool up to the reserve; the level falls back to
/// `NORMAL`; the fixture's next instance answers with a new nonce and no
/// pages held; and oomd's log holds one new line for the stop, after the
/// level had read `CRITICAL` for at least its grace. With `stopsrc.svc`
/// staged, the phase first has that stop source exit, so the instance svcmgr
/// restarts started after oomd, and start a job of [`JOB_PAGES`]: oomd stops
/// the job at its first act, before memhog at a later one, and the fixture
/// reports the job stopped. The phase opens an operator session whose leader
/// runs `crashme oom-hold` [`HOLD_PAGES`]:
/// oomd stops that job first, as the largest of the program class, then
/// `stopsrc`'s, then the sessions, then the fixture, and the session's relay
/// gives its leader's end. With crashd holding faults, a child
/// (`/tests/fixtures/programs/crashme oom-touch` [`TOUCH_PAGES`]) writes the pages of a
/// demand region in turn while the pool is full, once sessiond lists no
/// candidate, so that only memhog's stop is left: crashd holds the write
/// memmgr declines, and resumes it once the stop frees memory, so crashd logs
/// one more held and one more resumed fault and the child exits 0. crashd's
/// stall must outlast the act left from the write to memhog's stop, one
/// cooldown.
///
/// With `OOMD_STOP=no` (the no-stop case): the level stays `CRITICAL` past
/// oomd's grace and cooldown with the same instance of the fixture running and
/// no stop line logged, and at least one line naming a candidate it would
/// stop; svctest then stops the fixture itself,
/// through its stop authority, by the key svcmgr listed it under before the
/// fill, and the level falls back to `NORMAL`.
///
/// Between the fill and the fall of the level the phase allocates nothing and
/// touches no new stack page: a fault of its own would be declined or held.
fn oom_policy_phase(caps: &Caps)
{
    let phase = "oom_policy";
    if !fixtures::staged(Fixture::Memhog)
    {
        fixtures::skip(phase, Fixture::Memhog);
        return;
    }
    let config = oomd_config(phase);
    await_level(MemoryPressure::Normal, phase, "before the fill");
    let fixture = super::svcmgr::provided_endpoint(hog::NAME, phase);
    let (first, idle) = probe(fixture, phase, "PROBE before the fill");
    assert_eq!(
        idle, 0,
        "{phase}: memhog holds {idle} pages before the fill"
    );
    let before = Lines::read(caps.logd_query);

    if config.mode == oomd_policy::Mode::Stop
    {
        stop_case(caps, fixture, config, before, phase);
    }
    else
    {
        no_stop_case(caps, fixture, config, first, before, phase);
    }

    let (next, pages) = probe(fixture, phase, "PROBE after the stop");
    assert_ne!(next, first, "{phase}: the hogging instance still answered");
    assert_eq!(
        pages, 0,
        "{phase}: memhog's next instance holds {pages} pages"
    );
    let _ = syscall::cap_delete(fixture);
}

/// The stop case of [`oom_policy_phase`].
fn stop_case(caps: &Caps, fixture: u64, config: oomd_policy::Config, before: Lines, phase: &str)
{
    let job = fixtures::staged(Fixture::Stopsrc).then(|| Job::start(phase));
    let session = Held::start(caps, phase);
    let mut toucher = crashd_stall(phase).map(|stall_ms| {
        // The write follows the stop of the last program, the session's,
        // so oomd stops memhog one cooldown after it.
        let span_ms = config.cooldown_ms;
        assert!(
            stall_ms > span_ms,
            "{phase}: crashd's {stall_ms} ms stall does not outlast the {span_ms} ms oomd takes \
             from oom-touch's write to its stop of memhog"
        );
        Toucher::start(phase)
    });
    touch_stack();
    let pages = hog_call(fixture, phase);
    // crashd holds the toucher's fault for its stall alone, so the write
    // waits for oomd to have stopped every program, which leaves only the
    // fixture's stop before memory is freed. The last stop's pages lie free
    // until memhog's next top-up; the toucher's writes spend them
    // (`TOUCH_PAGES`).
    session.await_no_candidate(phase);
    if let Some(toucher) = &mut toucher
    {
        toucher
            .stdin
            .write_all(b"go\n")
            .unwrap_or_else(|e| panic!("{phase}: write to oom-touch: {e:?}"));
    }
    let fell_after = await_level(MemoryPressure::Normal, phase, "after the fill");

    let held_ms = toucher.map(|toucher| toucher.finish(phase));
    // oomd logs its line after the stop, and crashd its line after the
    // resume, so either can land after the level has fallen.
    let after = Lines::await_where(before.query, |now| {
        now.stops > before.stops
            && (held_ms.is_none() || now.resumed > before.resumed)
            && (job.is_none() || now.job_stops > before.job_stops)
            && now.hold_stops > before.hold_stops
    });
    if let Some(job) = &job
    {
        job.finish(&before, &after, phase);
    }
    let sessions = session.finish(&before, &after, job.as_ref(), phase);
    let stops = after.stops.saturating_sub(before.stops);
    assert_eq!(
        stops, 1,
        "{phase}: oomd logged {stops} stops of memhog for one episode (level fell after \
         {fell_after:?})"
    );
    assert_eq!(
        after.advice, before.advice,
        "{phase}: oomd advised in its stop mode"
    );
    let critical_ms = after.last_stop_critical_ms.unwrap_or(0);
    let job_line = if job.is_some()
    {
        format!(
            "; the session's job, stopsrc's job and the sessions ({sessions}) stopped first, in that \
             order"
        )
    }
    else
    {
        format!("; the session's job and the sessions ({sessions}) stopped first, in that order")
    };
    assert!(
        critical_ms >= config.grace_ms,
        "{phase}: oomd stopped memhog after {critical_ms} ms critical, inside its {} ms grace",
        config.grace_ms
    );
    if let Some(held_ms) = held_ms
    {
        assert!(
            after.held > before.held,
            "{phase}: crashd held none of oom-touch's {TOUCH_PAGES} writes: each found a free page"
        );
        assert!(
            after.resumed > before.resumed,
            "{phase}: crashd logged no resumed fault for oom-touch's held write"
        );
        std::os::seraph::log!(
            "oom phase passed (memhog hogged {pages} pages; oomd stopped it after {critical_ms} \
             ms critical{job_line}; oom-touch's write held {held_ms} ms and resumed)"
        );
    }
    else
    {
        std::os::seraph::log!(
            "oom phase passed (memhog hogged {pages} pages; oomd stopped it after {critical_ms} \
             ms critical{job_line}; crashd holds no fault, no held write)"
        );
    }
}

/// The no-stop case of [`oom_policy_phase`]: oomd advises (`config` with
/// `OOMD_STOP=no`).
fn no_stop_case(
    caps: &Caps,
    fixture: u64,
    config: oomd_policy::Config,
    first: u64,
    before: Lines,
    phase: &str,
)
{
    let watch_ms = config
        .grace_ms
        .saturating_add(config.cooldown_ms)
        .saturating_add(NO_STOP_MARGIN_MS);
    let stop_cap = caps.stop_authority;
    assert_ne!(
        stop_cap, 0,
        "{phase}: no stop-authority cap (stop_authority = yes)"
    );
    let key = super::svcmgr::list_candidates(stop_cap, phase)
        .iter()
        .find(|c| c.name == "memhog")
        .map_or(0, |c| c.key);
    touch_stack();
    let pages = hog_call(fixture, phase);
    let _ = syscall::thread_sleep(watch_ms);
    let level = std::os::seraph::memory_pressure();
    let (same, held) = probe(fixture, phase, "PROBE past the grace");
    // The fixture's next instance is idle, so the level the fixture held
    // falls once it is stopped below.
    let label = super::svcmgr::stop_candidate(stop_cap, key);
    let _ = await_level(MemoryPressure::Normal, phase, "after svctest's stop");
    assert_eq!(
        level,
        Some(MemoryPressure::Critical),
        "{phase}: the level fell within {watch_ms} ms of the fill with no stop"
    );
    assert_eq!(
        same, first,
        "{phase}: memhog was stopped with no stop allowed"
    );
    assert!(
        held >= pages,
        "{phase}: memhog holds {held} of its {pages} pages"
    );
    assert_eq!(
        label,
        ipc::stop_labels::SUCCESS,
        "{phase}: STOP_CANDIDATE(memhog) replied {label:#x}"
    );
    let after = Lines::await_where(before.query, |now| now.advice > before.advice);
    assert_eq!(
        after.stops, before.stops,
        "{phase}: oomd stopped memhog with no stop allowed"
    );
    let advice = after.advice.saturating_sub(before.advice);
    assert!(advice >= 1, "{phase}: oomd named nothing it would stop");
    std::os::seraph::log!(
        "oom phase passed (OOMD_STOP=no: memhog held {pages} pages for {watch_ms} ms unstopped, oomd \
         advised {advice} times; stopped by svctest)"
    );
}

/// The fixture's nonce and the pages it holds, read through `fixture`;
/// `what` names the read in a failure. Allocates nothing.
fn probe(fixture: u64, phase: &str, what: &str) -> (u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(fixture, &ipc::IpcMessage::new(hog::PROBE), ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: {what} call failed: {e:?}"));
    assert_eq!(
        reply.label,
        hog::SUCCESS,
        "{phase}: {what} reply {:#x}",
        reply.label
    );
    (reply.word(0), reply.word(1))
}

/// Hold the level at `CRITICAL` for `phase`, through the `memhog` fixture,
/// which the staged set must declare ([`super::fixtures`]): wait for
/// `NORMAL`, have the fixture fill the pool down to the growth floor, run
/// `during` once the level reads `CRITICAL`, and wait for the level to fall
/// back to `NORMAL`. oomd's stop of the fixture ends the window when oomd's
/// recipe sets its stop mode, at least its grace after the fill; otherwise
/// svctest stops the fixture itself, through its stop authority, `hold` after
/// the fill. The fixture's
/// next instance must then answer with a new nonce and no pages.
///
/// From the fill to the fixture's stop the fixture holds the pool at the growth
/// floor, so a process outside the system reserve takes no free page, except
/// the pages another process frees in the window, which the fixture takes back
/// only at its next tick (`mem_fill::TICK_MS`). Fails `phase` when the level
/// does not read `CRITICAL` after the fill, or `NORMAL` after the window,
/// within [`NORMAL_WAIT`]. `during`, the reads of the level and the stop must
/// allocate nothing and write no log line; the stack they use is touched before
/// the fill.
pub(super) fn critical_window(caps: &Caps, phase: &str, hold: Duration, during: impl FnOnce())
{
    let stops = oomd_config(phase).mode == oomd_policy::Mode::Stop;
    await_level(MemoryPressure::Normal, phase, "before the fill");
    let fixture = super::svcmgr::provided_endpoint(hog::NAME, phase);
    let (first, idle) = probe(fixture, phase, "PROBE before the fill");
    assert_eq!(
        idle, 0,
        "{phase}: memhog holds {idle} pages before the fill"
    );
    let own_stop = (!stops).then(|| {
        let cap = caps.stop_authority;
        assert_ne!(
            cap, 0,
            "{phase}: no stop-authority cap (stop_authority = yes)"
        );
        let key = super::svcmgr::list_candidates(cap, phase)
            .iter()
            .find(|c| c.name == "memhog")
            .map_or_else(
                || panic!("{phase}: svcmgr lists no memhog candidate"),
                |c| c.key,
            );
        (cap, key)
    });
    touch_stack();
    let _ = hog_call(fixture, phase);
    await_level(MemoryPressure::Critical, phase, "after the fill");
    during();
    if let Some((cap, key)) = own_stop
    {
        let _ = syscall::thread_sleep(u64::try_from(hold.as_millis()).unwrap_or(u64::MAX));
        let label = super::svcmgr::stop_candidate(cap, key);
        assert_eq!(
            label,
            ipc::stop_labels::SUCCESS,
            "{phase}: STOP_CANDIDATE(memhog) replied {label:#x}"
        );
    }
    await_level(MemoryPressure::Normal, phase, "after the window");
    let (next, pages) = probe(fixture, phase, "PROBE after the window");
    assert_ne!(next, first, "{phase}: the hogging instance still answered");
    assert_eq!(
        pages, 0,
        "{phase}: memhog's next instance holds {pages} pages"
    );
    let _ = syscall::cap_delete(fixture);
}

/// Microseconds since boot, the clock logd stamps each history entry with
/// (`ElapsedUs`).
pub(super) fn elapsed_us() -> u64
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64)
        .unwrap_or_else(|e| panic!("system_info(ElapsedUs) failed ({e})"))
}

/// Have the fixture fill the pool down to the growth floor: the pages it holds
/// once the level has settled at `CRITICAL`. Allocates nothing.
fn hog_call(fixture: u64, phase: &str) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(fixture, &ipc::IpcMessage::new(hog::HOG), ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: HOG call failed: {e:?}"));
    assert_eq!(
        reply.label,
        hog::SUCCESS,
        "{phase}: HOG reply {:#x}",
        reply.label
    );
    reply.word(0)
}

/// Wait up to [`NORMAL_WAIT`] for the level to read `level`, and return how
/// long it took; `when` names the wait in a failure. Allocates nothing until
/// it fails.
fn await_level(level: MemoryPressure, phase: &str, when: &str) -> Duration
{
    let start = Instant::now();
    loop
    {
        let read = std::os::seraph::memory_pressure();
        if read == Some(level)
        {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < NORMAL_WAIT,
            "{phase}: the level read {read:?}, not {level:?}, {NORMAL_WAIT:?} {when}"
        );
        std::thread::sleep(LEVEL_POLL);
    }
}

/// The counts of the log lines the phase reads, across logd's history.
#[derive(Clone, Copy)]
struct Lines
{
    query: u64,
    /// oomd's stops of the fixture.
    stops: usize,
    /// oomd's stops of `stopsrc`'s job.
    job_stops: usize,
    /// Whether the newest stop of the job was logged before the newest stop
    /// of the fixture.
    job_first: bool,
    /// oomd's stops of the session's job.
    hold_stops: usize,
    /// oomd's stops of sessions.
    session_stops: usize,
    /// Where in the history, newest first, the newest stop of the session's
    /// job, of `stopsrc`'s job and of the fixture, and the newest and the
    /// oldest stop of a session, sit.
    at: Positions,
    /// oomd's advice lines, each naming a candidate it would stop.
    advice: usize,
    /// crashd's held faults.
    held: usize,
    /// crashd's resumed held faults.
    resumed: usize,
    /// The milliseconds critical the newest stop line gives.
    last_stop_critical_ms: Option<u64>,
}

impl Lines
{
    /// The counts once `done` holds of them, read every [`LEVEL_POLL`]
    /// for up to [`LOG_WAIT`]; the last counts read when it never does.
    fn await_where(query: u64, done: impl Fn(&Self) -> bool) -> Self
    {
        let start = Instant::now();
        loop
        {
            let lines = Self::read(query);
            if done(&lines) || start.elapsed() > LOG_WAIT
            {
                return lines;
            }
            std::thread::sleep(LEVEL_POLL);
        }
    }

    /// The counts in logd's history now, read through `query`.
    fn read(query: u64) -> Self
    {
        let history = super::procmgr::logd_history(query, None);
        let count = |needle: &[u8]| {
            history
                .iter()
                .filter(|(_, bytes)| contains(bytes, needle))
                .count()
        };
        // Newest first: the first stop line is the last logged.
        let newest = |needle: &[u8]| {
            history
                .iter()
                .position(|(_, bytes)| contains(bytes, needle))
        };
        let last_stop_critical_ms = history
            .iter()
            .find(|(_, bytes)| contains(bytes, STOP_LINE))
            .and_then(|(_, bytes)| critical_ms(bytes));
        // Newest first: the line logged first sits further down.
        let oldest = |needle: &[u8]| {
            history
                .iter()
                .rposition(|(_, bytes)| contains(bytes, needle))
        };
        let job_first = matches!(
            (newest(JOB_STOP_LINE), newest(STOP_LINE)),
            (Some(job), Some(hog)) if job > hog
        );
        Self {
            query,
            stops: count(STOP_LINE),
            job_stops: count(JOB_STOP_LINE),
            job_first,
            hold_stops: count(HOLD_STOP_LINE),
            session_stops: count(SESSION_STOP_LINE),
            at: Positions {
                hold: newest(HOLD_STOP_LINE),
                job: newest(JOB_STOP_LINE),
                hog: newest(STOP_LINE),
                session_newest: newest(SESSION_STOP_LINE),
                session_oldest: oldest(SESSION_STOP_LINE),
            },
            advice: count(ADVICE_LINE),
            held: count(HELD_LINE),
            resumed: count(RESUMED_LINE),
            last_stop_critical_ms,
        }
    }
}

/// Positions in logd's history, newest first, of oomd's stop lines; see
/// [`Lines::at`].
#[derive(Clone, Copy)]
struct Positions
{
    hold: Option<usize>,
    job: Option<usize>,
    hog: Option<usize>,
    session_newest: Option<usize>,
    session_oldest: Option<usize>,
}

/// The milliseconds an oomd stop line gives the level as critical for:
/// `... memory critical for <ms> ms`.
fn critical_ms(line: &[u8]) -> Option<u64>
{
    let text = core::str::from_utf8(line).ok()?;
    let (_, rest) = text.split_once("critical for ")?;
    rest.split(' ').next()?.parse().ok()
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool
{
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The job the stop case has the `stopsrc` fixture start: the SEND on the
/// fixture's provided name, and the job's key.
struct Job
{
    fixture: u64,
    key: u64,
}

impl Job
{
    /// Have the fixture exit, wait for its restarted instance's new nonce,
    /// then have that instance start a job of [`JOB_PAGES`]. svcmgr starts
    /// the new instance after oomd, so oomd finds the source only by its walk
    /// at the act.
    fn start(phase: &str) -> Self
    {
        let fixture = super::svcmgr::provided_endpoint(src::NAME, phase);
        let (first, _, _) = src_call(fixture, src::PROBE, 0, phase, "stopsrc PROBE");
        let _ = src_call(fixture, src::EXIT, 0, phase, "stopsrc EXIT");
        let (next, state, _) = src_call(fixture, src::PROBE, 0, phase, "stopsrc PROBE after EXIT");
        assert!(
            next != first && state == src::JOB_NONE,
            "{phase}: stopsrc did not restart (nonce {first:#x} then {next:#x}, job {state})"
        );
        let (key, _, _) = src_call(
            fixture,
            src::START_JOB,
            JOB_PAGES,
            phase,
            "stopsrc START_JOB",
        );
        Self { fixture, key }
    }

    /// Check that oomd logged one stop of the job, before its stop of memhog,
    /// and that the fixture reports the job stopped.
    fn finish(&self, before: &Lines, after: &Lines, phase: &str)
    {
        let stops = after.job_stops.saturating_sub(before.job_stops);
        assert!(
            stops == 1 && after.job_first,
            "{phase}: oomd logged {stops} stops of stopsrc's job, first: {}",
            after.job_first
        );
        let (_, state, key) = src_call(self.fixture, src::PROBE, 0, phase, "stopsrc PROBE");
        assert!(
            state == src::JOB_STOPPED && key == 0,
            "{phase}: stopsrc's job {} reads state {state}, key {key}",
            self.key
        );
        let _ = syscall::cap_delete(self.fixture);
    }
}

/// Call `label` with `data[0] = word` on the `stopsrc` fixture: the reply's
/// first three data words. Fails `phase` on a reply other than `SUCCESS`.
pub(super) fn src_call(
    fixture: u64,
    label: u64,
    word: u64,
    phase: &str,
    what: &str,
) -> (u64, u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(label).word(0, word).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(fixture, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: {what} call failed: {e:?}"));
    assert_eq!(
        reply.label,
        src::SUCCESS,
        "{phase}: {what} reply {:#x}",
        reply.label
    );
    (reply.word(0), reply.word(1), reply.word(2))
}

/// The operator session the stop case opens, whose leader runs
/// `crashme oom-hold` [`HOLD_PAGES`]: a job of the program class larger
/// than `stopsrc`'s.
struct Held
{
    session: super::sessiond::Session,
    /// sessiond's stop SEND, read before the fill so the poll of its
    /// candidates allocates nothing.
    send: u64,
}

impl Held
{
    /// Open the session and start its job; return once the job holds its
    /// pages.
    fn start(caps: &Caps, phase: &str) -> Self
    {
        let send = super::sessiond::stop_send(caps, phase);
        let mut session = super::sessiond::Session::open(caps.sessiond_operator, phase);
        session.send(&format!("{CRASHME_PATH} oom-hold {HOLD_PAGES}"), phase);
        session.expect(&format!("holding {HOLD_PAGES}"), phase);
        Self { session, send }
    }

    /// Wait, up to [`NORMAL_WAIT`], for sessiond to list no candidate: oomd
    /// has stopped every session and job, or the level has fallen first,
    /// which the checks after report. Allocates nothing until it fails.
    fn await_no_candidate(&self, phase: &str)
    {
        let start = Instant::now();
        while super::sessiond::candidate_count(self.send, phase) != 0
            && std::os::seraph::memory_pressure() == Some(MemoryPressure::Critical)
        {
            assert!(
                start.elapsed() < NORMAL_WAIT,
                "{phase}: sessiond still lists candidates {NORMAL_WAIT:?} after the fill"
            );
            std::thread::sleep(LEVEL_POLL);
        }
    }

    /// Check that oomd stopped the session's job once, first, before
    /// `stopsrc`'s job when that ran (`job`), every session after the
    /// jobs and before the fixture, and that the session ended: the number
    /// of sessions oomd stopped.
    fn finish(self, before: &Lines, after: &Lines, job: Option<&Job>, phase: &str) -> usize
    {
        let hold_stops = after.hold_stops.saturating_sub(before.hold_stops);
        assert_eq!(
            hold_stops, 1,
            "{phase}: oomd logged {hold_stops} stops of the session's job"
        );
        let at = after.at;
        let before_hog = |pos: Option<usize>| matches!((pos, at.hog), (Some(p), Some(h)) if p > h);
        assert!(
            before_hog(at.hold),
            "{phase}: oomd stopped the session's job after memhog"
        );
        let last_job = if job.is_some()
        {
            assert!(
                matches!((at.hold, at.job), (Some(h), Some(j)) if h > j),
                "{phase}: oomd stopped stopsrc's smaller job before the session's"
            );
            at.job
        }
        else
        {
            at.hold
        };
        let sessions = after.session_stops.saturating_sub(before.session_stops);
        if sessions > 0
        {
            assert!(
                matches!((last_job, at.session_oldest), (Some(j), Some(s)) if j > s)
                    && before_hog(at.session_newest),
                "{phase}: oomd stopped a session before a job, or after memhog"
            );
        }
        let status = self.session.wait(phase);
        assert!(
            !status.success(),
            "{phase}: the session's leader exited cleanly while oomd stopped programs"
        );
        let _ = syscall::cap_delete(self.send);
        sessions
    }
}

/// A `/tests/fixtures/programs/crashme oom-touch` [`TOUCH_PAGES`] child, between its
/// `ready` and its writes.
struct Toucher
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Toucher
{
    /// Start the child and wait for its `ready`, which it prints with its
    /// demand region registered and its buffers made.
    fn start(phase: &str) -> Self
    {
        let mut child = Command::new("/tests/fixtures/programs/crashme")
            .arg("oom-touch")
            .arg(TOUCH_PAGES.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("{phase}: spawn /tests/fixtures/programs/crashme oom-touch: {e:?}")
            });
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::with_capacity(256);
        stdin
            .write_all(b"start\n")
            .unwrap_or_else(|e| panic!("{phase}: write to oom-touch: {e:?}"));
        stdout
            .read_line(&mut line)
            .unwrap_or_else(|e| panic!("{phase}: read oom-touch: {e:?}"));
        assert_eq!(line.trim(), "ready", "{phase}: oom-touch printed {line:?}");
        line.clear();
        Self {
            child,
            stdin,
            stdout,
            line,
        }
    }

    /// Read the child's line and wait for its exit, once the level has
    /// fallen: how long its longest write took, the one crashd held. The
    /// child prints the line when its writes complete, and dies of the fault,
    /// printing none, when the hold times out.
    fn finish(mut self, phase: &str) -> u64
    {
        let _ = self.stdout.read_line(&mut self.line);
        let start = Instant::now();
        let status = loop
        {
            if let Some(status) = self.child.try_wait().expect("try_wait")
            {
                break status;
            }
            if start.elapsed() > CHILD_WAIT
            {
                let _ = self.child.kill();
                panic!("{phase}: oom-touch still running {CHILD_WAIT:?} after the level fell");
            }
            std::thread::sleep(LEVEL_POLL);
        };
        let held = self
            .line
            .trim()
            .strip_prefix("touched held_ms=")
            .and_then(|ms| ms.parse::<u64>().ok());
        match held
        {
            Some(ms) if status.success() => ms,
            _ => panic!(
                "{phase}: oom-touch {status}, {:?}: its write was not held and resumed",
                self.line
            ),
        }
    }
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the phase
/// faults no new stack page while the pool is full.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the window may use, written once before it"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}
