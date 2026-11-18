// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/oom.rs

//! The out-of-memory policy end to end (services/oomd/docs/operation.md): the
//! `memhog` fixture fills memmgr's pool up to the system reserve, and oomd
//! stops it once the level has read `CRITICAL` for its grace, or, with
//! `OOMD_STOP=no` or no oomd, nothing stops it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ipc::memhog_labels as hog;
use std::os::seraph::MemoryPressure;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The recipe that starts the `memhog` fixture, when it is staged for this
/// boot.
pub const MEMHOG_RECIPE: &str = "/config/svcmgr/services/memhog.svc";

/// oomd's recipe, when the image starts oomd.
const OOMD_RECIPE: &str = "/config/svcmgr/services/oomd.svc";

/// crashd's recipe, when the image starts crashd.
const CRASHD_RECIPE: &str = "/config/svcmgr/services/crashd.svc";

/// How long the phase waits for the level to read `NORMAL`: before the
/// fill, for what earlier phases left, and after it, for oomd's grace, its
/// stop, and memmgr's reclaim of the fixture's memory. A test wait bound.
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

/// The prefix of oomd's line for a stop of the fixture it advises.
const ADVICE_LINE: &[u8] = b"would stop memhog: ";

/// The part of crashd's line for a held fault it resumed.
const RESUMED_LINE: &[u8] = b"resumed after";

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "oom_policy",
        run: oom_policy_phase,
    }]
}

/// What oomd's recipe sets, as oomd reads it (`oomd_policy`); `None` when
/// the image does not start oomd.
fn oomd_config(phase: &str) -> Option<oomd_policy::Config>
{
    let recipe = recipe_text(OOMD_RECIPE, phase)?;
    let grace = oomd_policy::parse_ms(
        env_value(&recipe, "OOMD_GRACE_MS"),
        oomd_policy::GRACE_DEFAULT_MS,
    );
    let cooldown = oomd_policy::parse_ms(
        env_value(&recipe, "OOMD_COOLDOWN_MS"),
        oomd_policy::COOLDOWN_DEFAULT_MS,
    );
    Some(oomd_policy::Config {
        grace_ms: grace.value,
        cooldown_ms: cooldown.value,
        mode: oomd_policy::parse_stop(env_value(&recipe, "OOMD_STOP")).value,
    })
}

/// Whether crashd runs and holds a fault declined for want of memory: its
/// recipe is staged and sets a non-zero `CRASHD_OOM_STALL_MS`.
fn crashd_holds(phase: &str) -> bool
{
    recipe_text(CRASHD_RECIPE, phase).is_some_and(|recipe| {
        env_value(&recipe, "CRASHD_OOM_STALL_MS")
            .and_then(|ms| ms.parse::<u64>().ok())
            .is_some_and(|ms| ms != 0)
    })
}

/// The text of the recipe at `path`; `None` when it is not staged.
fn recipe_text(path: &str, phase: &str) -> Option<String>
{
    super::svcmgr::recipe_staged(path, phase).then(|| {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{phase}: read {path}: {e:?}"))
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
/// passes without it, which leaves no service oomd may stop.
///
/// With oomd's recipe staged and `OOMD_STOP` not `no` (the stop case): the
/// fixture fills the pool up to the reserve; the level falls back to
/// `NORMAL`; the fixture's next instance answers with a new nonce and no
/// pages held; and oomd's log holds one new line for the stop, after the
/// level had read `CRITICAL` for at least its grace. With crashd holding
/// faults, a child (`/programs/crashme oom-touch`) writes a demand page
/// while the pool is full: crashd holds the fault, and resumes it once the
/// stop frees memory, so the child exits 0 and crashd logs one more resumed
/// fault.
///
/// With `OOMD_STOP=no`, or no oomd (the no-stop case): the level stays
/// `CRITICAL` past oomd's grace and cooldown with the same instance of the
/// fixture running and no stop line logged, and, with oomd, at least one line
/// naming the fixture it would stop; svctest then stops the fixture itself,
/// through its stop authority, and the level falls back to `NORMAL`.
///
/// Between the fill and the fall of the level the phase allocates nothing and
/// touches no new stack page: a fault of its own would be declined or held.
fn oom_policy_phase(caps: &Caps)
{
    let phase = "oom_policy";
    if !super::svcmgr::recipe_staged(MEMHOG_RECIPE, phase)
    {
        std::os::seraph::log!("oom phase passed (memhog.svc not staged)");
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

    match config
    {
        Some(config) if config.mode == oomd_policy::Mode::Stop =>
        {
            stop_case(fixture, config, before, phase);
        }
        _ => no_stop_case(caps, fixture, config, first, before, phase),
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
fn stop_case(fixture: u64, config: oomd_policy::Config, before: Lines, phase: &str)
{
    let mut toucher = crashd_holds(phase).then(|| Toucher::start(phase));
    touch_stack();
    let pages = hog_call(fixture, phase);
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
        now.stops > before.stops && (held_ms.is_none() || now.resumed > before.resumed)
    });
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
    assert!(
        critical_ms >= config.grace_ms,
        "{phase}: oomd stopped memhog after {critical_ms} ms critical, inside its {} ms grace",
        config.grace_ms
    );
    if let Some(held_ms) = held_ms
    {
        assert!(
            after.resumed > before.resumed,
            "{phase}: crashd logged no resumed fault for oom-touch's held write"
        );
        std::os::seraph::log!(
            "oom phase passed (memhog hogged {pages} pages; oomd stopped it after {critical_ms} \
             ms critical; oom-touch's write held {held_ms} ms and resumed)"
        );
    }
    else
    {
        std::os::seraph::log!(
            "oom phase passed (memhog hogged {pages} pages; oomd stopped it after {critical_ms} \
             ms critical; crashd holds no fault, no held write)"
        );
    }
}

/// The no-stop case of [`oom_policy_phase`]: oomd advises (`config` with
/// `OOMD_STOP=no`) or is absent (`None`).
fn no_stop_case(
    caps: &Caps,
    fixture: u64,
    config: Option<oomd_policy::Config>,
    first: u64,
    before: Lines,
    phase: &str,
)
{
    let watch_ms = config
        .map_or(
            oomd_policy::GRACE_DEFAULT_MS + oomd_policy::COOLDOWN_DEFAULT_MS,
            |c| c.grace_ms.saturating_add(c.cooldown_ms),
        )
        .saturating_add(NO_STOP_MARGIN_MS);
    let stop_cap = caps.stop_authority;
    assert_ne!(
        stop_cap, 0,
        "{phase}: no stop-authority cap (stop_authority = yes)"
    );
    touch_stack();
    let pages = hog_call(fixture, phase);
    let _ = syscall::thread_sleep(watch_ms);
    let level = std::os::seraph::memory_pressure();
    let (same, held) = probe(fixture, phase, "PROBE past the grace");
    // The fixture's next instance is idle, so the level the fixture held
    // falls once it is stopped below.
    let label = super::svcmgr::stop_service(stop_cap, b"memhog");
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
        ipc::svcmgr_errors::SUCCESS,
        "{phase}: STOP_SERVICE(memhog) replied {label:#x}"
    );
    let after = Lines::await_where(before.query, |now| {
        config.is_none() || now.advice > before.advice
    });
    assert_eq!(
        after.stops, before.stops,
        "{phase}: oomd stopped memhog with no stop allowed"
    );
    let advice = after.advice.saturating_sub(before.advice);
    let shown = if config.is_some()
    {
        assert!(advice >= 1, "{phase}: oomd named nothing it would stop");
        "OOMD_STOP=no"
    }
    else
    {
        "oomd.svc not staged"
    };
    std::os::seraph::log!(
        "oom phase passed ({shown}: memhog held {pages} pages for {watch_ms} ms unstopped, oomd \
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

/// Have the fixture fill the pool up to the reserve: the pages it holds once
/// the level has settled at `CRITICAL`. Allocates nothing.
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
    /// oomd's advice to stop the fixture.
    advice: usize,
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
        let last_stop_critical_ms = history
            .iter()
            .find(|(_, bytes)| contains(bytes, STOP_LINE))
            .and_then(|(_, bytes)| critical_ms(bytes));
        Self {
            query,
            stops: count(STOP_LINE),
            advice: count(ADVICE_LINE),
            resumed: count(RESUMED_LINE),
            last_stop_critical_ms,
        }
    }
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

/// A `/programs/crashme oom-touch` child, between its `ready` and its
/// write.
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
    /// demand page registered and its buffers made.
    fn start(phase: &str) -> Self
    {
        let mut child = Command::new("/programs/crashme")
            .arg("oom-touch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{phase}: spawn /programs/crashme oom-touch: {e:?}"));
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
    /// fallen: how long its write was held. The child prints the line when
    /// the write completes, and dies of the fault, printing none, when the
    /// hold times out.
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
