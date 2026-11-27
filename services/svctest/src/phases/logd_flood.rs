// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_flood.rs

//! A log flood holds back only the senders that flood
//! (`services/logd/docs/ipc-interface.md` § Hold window).
//!
//! svctest is the probe. Between its `log-flood begin` and `log-flood end`
//! lines it makes [`PROBE_CALLS`] raw `STREAM_BYTES` calls, one every
//! [`QUIET_GAP`], with no flood, and as many again, one every [`FLOODED_GAP`],
//! while two child processes flood logd:
//!
//! - a flooder, whose [`FLOOD_THREADS`] threads, more than logd's four
//!   receive workers (`RECV_WORKERS`), log through `seraph::log!` as fast as
//!   logd takes their lines, the log client waiting out each `WINDOW_FULL`
//!   refusal's hint;
//! - a resender, which sends each line again at once when logd refuses it
//!   `WINDOW_FULL`, and must have been refused.
//!
//! On a boot with a framebuffer driver the phase also stops that driver for
//! the flooded calls: logd's `skip` framebuffer sink holds nobody, so the
//! probe's times hold with it stopped. Its default level, critical, shows
//! none of the flood's lines, so it drops none of them; the `logd_sinks`
//! phase's framebuffer-stopped case checks its drops.
//!
//! The phase requires:
//!
//! - the median of the probe's flooded calls within [`FLOODED_TO_QUIET`]
//!   times the median of its calls with no flood, where a call that waited
//!   on a sink behind the flood's lines would take the time of their writes;
//!   its slowest calls are logged, not bounded: under the flood they meet
//!   the resender's refusals at logd's state lock, whose waiter parks in
//!   steps of a millisecond (`runtime/ruststd/spin-wait`);
//! - no probe call refused: only the flooders' own lines are refused;
//! - both children still flooding when the probe's last call returns.
//!
//! Each probe line is numbered, `log-flood t=0 n=<n> len=<len> <payload>`, and
//! the end line names them all, so the boot's `cargo xtask run --whole-lines
//! log-flood` check requires every probe line on serial whole, in `seq` order,
//! none missing (`xtask/README.md` § `--whole-lines`).

use std::process::Command;
use std::time::{Duration, Instant};

use ipc::IpcMessage;
use ipc::stream_labels::{LEVEL_INFO, STREAM_BYTES, WINDOW_FULL, level_bits};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "logd_flood",
        run: logd_flood_phase,
    }]
}

/// The tag of the phase's whole-lines window.
const TAG: &str = "log-flood";

/// The probe's calls with no flood, and again under it.
const PROBE_CALLS: usize = 200;

/// The probe's pause between its calls with no flood: longer than the serial
/// sink takes to write a line, so the probe's own lines stay within its hold
/// window.
const QUIET_GAP: Duration = Duration::from_millis(10);

/// The probe's pause between its flooded calls. The serial sink writes in
/// `seq` order, so each probe line waits behind the flooders' two full
/// windows, `2 * HOLD_WINDOW` lines: with the sink taking `w` a line, the
/// probe holds `2 * HOLD_WINDOW * w / (gap - w)` lines unwritten, within its
/// window while the gap is at least `3 * w`. 30 ms keeps the probe a sender
/// within its share of the sink up to 10 ms a line, past what a loaded host's
/// x86_64 boot takes (about 8 ms; 3 ms unloaded).
const FLOODED_GAP: Duration = Duration::from_millis(30);

/// The flooder's threads: logd's four receive workers (`RECV_WORKERS`) and
/// two more.
const FLOOD_THREADS: u64 = 4 + 2;

/// How long each child floods: past the probe's flooded calls, which take
/// [`PROBE_CALLS`] times [`FLOODED_GAP`], 6 s, and their own time.
const FLOOD_FOR: Duration = Duration::from_secs(9);

/// How long the phase lets the children start flooding before the probe's
/// flooded calls.
const FLOOD_SETTLE: Duration = Duration::from_millis(300);

/// The median of the probe's flooded calls, at most, in medians of its calls
/// with no flood.
const FLOODED_TO_QUIET: u32 = 10;

/// The flooder's role (`crate::reentry`).
const FLOODER_ROLE: &str = "log-flooder";

/// The resender's role.
const RESENDER_ROLE: &str = "log-resender";

/// The resender's exit code when logd refused none of its lines.
const RESENDER_NEVER_REFUSED: i32 = 3;

/// The shortest numbered line's payload, in letters.
const PAYLOAD_MIN: usize = 8;

/// The payload lengths' spread above [`PAYLOAD_MIN`].
const PAYLOAD_SPREAD: usize = 40;

/// What the probe saw of its calls.
struct Probe
{
    /// Each call's time, in the order made.
    took: Vec<Duration>,
    /// The calls logd refused `WINDOW_FULL`.
    refused: usize,
}

/// Run the probe with no flood and under it (see the module documentation).
fn logd_flood_phase(caps: &Caps)
{
    std::os::seraph::log!("{TAG} begin");
    let quiet = probe(0, QUIET_GAP).unwrap_or_else(|e| panic!("{e}"));

    let mut flood_child = Command::new("/tests/svctest")
        .arg(FLOODER_ROLE)
        .spawn()
        .expect("logd_flood: spawning the flooder failed");
    let mut resend_child = Command::new("/tests/svctest")
        .arg(RESENDER_ROLE)
        .spawn()
        .expect("logd_flood: spawning the resender failed");
    std::thread::sleep(FLOOD_SETTLE);
    let fb = stop_framebuffer(caps.debug_authority);
    let flooded = probe(PROBE_CALLS, FLOODED_GAP);
    let flooding =
        matches!(flood_child.try_wait(), Ok(None)) && matches!(resend_child.try_wait(), Ok(None));
    if let Some((process, threads)) = fb
    {
        super::logd_sinks::start(&threads, "framebuffer");
        super::logd_sinks::detach(caps.debug_authority, process, threads, "framebuffer");
    }
    let flooded = flooded.unwrap_or_else(|e| panic!("{e}"));
    let flood_exit = flood_child
        .wait()
        .expect("logd_flood: waiting for the flooder failed");
    let resender = resend_child
        .wait()
        .expect("logd_flood: waiting for the resender failed");
    std::os::seraph::log!(
        "{TAG} end senders=1 lines={}",
        PROBE_CALLS.saturating_mul(2)
    );

    assert_eq!(
        flood_exit.code(),
        Some(0),
        "logd_flood: the flooder failed: {flood_exit}"
    );
    assert_ne!(
        resender.code(),
        Some(RESENDER_NEVER_REFUSED),
        "logd_flood: logd refused none of the resender's lines: no window filled"
    );
    assert_eq!(
        resender.code(),
        Some(0),
        "logd_flood: the resender failed: {resender}"
    );
    assert!(
        flooding,
        "logd_flood: a child stopped flooding before the probe's last call; raise FLOOD_FOR"
    );
    assert_eq!(
        quiet.refused.saturating_add(flooded.refused),
        0,
        "logd_flood: logd refused {} of the probe's lines with no flood and {} under it",
        quiet.refused,
        flooded.refused
    );
    let median = quantile(&quiet.took, 50);
    let slowest = quantile(&flooded.took, 100);
    std::os::seraph::log!(
        "logd_flood: probe calls with no flood: median {} us, 99th percentile {} us, slowest {} \
         us; under {FLOOD_THREADS} flooding threads and a resender: median {} us, 99th \
         percentile {} us, slowest {} us",
        median.as_micros(),
        quantile(&quiet.took, 99).as_micros(),
        quantile(&quiet.took, 100).as_micros(),
        quantile(&flooded.took, 50).as_micros(),
        quantile(&flooded.took, 99).as_micros(),
        slowest.as_micros()
    );
    let flooded_median = quantile(&flooded.took, 50);
    assert!(
        flooded_median <= median.saturating_mul(FLOODED_TO_QUIET),
        "logd_flood: the probe's median flooded call took {} us, past {FLOODED_TO_QUIET} times \
         its median of {} us with no flood",
        flooded_median.as_micros(),
        median.as_micros()
    );
}

/// Stop every thread of the framebuffer driver, when the boot has one: its
/// process and thread caps.
fn stop_framebuffer(authority: u64) -> Option<(u64, Vec<u64>)>
{
    let fb = super::crash::badge_named(authority, super::logd_sinks::FRAMEBUFFER_NAME)?;
    let threads = super::logd_sinks::attach(authority, fb, "framebuffer");
    super::logd_sinks::stop(&threads, "framebuffer");
    Some((fb, threads))
}

/// Make [`PROBE_CALLS`] numbered calls from `first`, one every `gap`:
/// what the probe saw, or the first failure. A refused line
/// is sent again after its hint, so that the console check finds it, and
/// counted. No assertion panics here, since the framebuffer driver may be
/// stopped.
fn probe(first: usize, gap: Duration) -> Result<Probe, String>
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = log::LOG_CALL_TIMEOUT_MS;
    let mut seen = Probe {
        took: Vec::with_capacity(PROBE_CALLS),
        refused: 0,
    };
    for n in first..first.saturating_add(PROBE_CALLS)
    {
        let len = PAYLOAD_MIN.saturating_add(n % PAYLOAD_SPREAD);
        let payload: String = (0..len)
            .map(|i| char::from(b'a'.saturating_add(u8::try_from(i % 26).unwrap_or(0))))
            .collect();
        let line = format!("{TAG} t=0 n={n} len={len} {payload}\n");
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
        let msg = IpcMessage::builder(label).bytes(0, line.as_bytes()).build();
        loop
        {
            let start_at = Instant::now();
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            let reply = unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }
                .map_err(|e| format!("logd_flood: probe call {n} not answered ({e})"))?;
            seen.took.push(start_at.elapsed());
            match reply.label
            {
                0 => break,
                WINDOW_FULL =>
                {
                    seen.refused = seen.refused.saturating_add(1);
                    std::thread::sleep(Duration::from_millis(reply.word(0)));
                }
                other => return Err(format!("logd_flood: probe call {n} refused ({other:#x})")),
            }
        }
        std::thread::sleep(gap);
    }
    Ok(seen)
}

/// The `percent`th percentile of `took`, by the nearest rank: the median at
/// 50, the slowest at 100.
fn quantile(took: &[Duration], percent: usize) -> Duration
{
    let mut sorted = took.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted
        .get(rank.saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

/// Child-mode dispatch for this module's roles (`crate::reentry`).
pub fn reentry_main(role: &str)
{
    if role == FLOODER_ROLE
    {
        flooder_main();
    }
    if role == RESENDER_ROLE
    {
        resender_main();
    }
}

/// The flooder: [`FLOOD_THREADS`] threads log numbered lines through
/// `seraph::log!` for [`FLOOD_FOR`].
fn flooder_main() -> !
{
    std::os::seraph::log::register_name(b"logflood");
    let start_at = Instant::now();
    std::thread::scope(|scope| {
        for t in 0..FLOOD_THREADS
        {
            scope.spawn(move || {
                let mut n = 0u64;
                while start_at.elapsed() < FLOOD_FOR
                {
                    std::os::seraph::log!("flood {t}.{n}");
                    n = n.saturating_add(1);
                }
            });
        }
    });
    std::process::exit(0);
}

/// The resender: for [`FLOOD_FOR`], raw `STREAM_BYTES` calls of numbered
/// lines, each sent again at once while logd refuses it `WINDOW_FULL`. Exits
/// 0 once refused at least once, [`RESENDER_NEVER_REFUSED`] if never, 1 on a
/// failed call.
fn resender_main() -> !
{
    std::os::seraph::log::register_name(b"logresend");
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = log::LOG_CALL_TIMEOUT_MS;
    let start_at = Instant::now();
    let mut sent = 0u64;
    let mut refused = 0u64;
    while start_at.elapsed() < FLOOD_FOR
    {
        let line = format!("resend {sent}\n");
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
        let msg = IpcMessage::builder(label).bytes(0, line.as_bytes()).build();
        loop
        {
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            match unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }
            {
                Ok(reply) if reply.label == 0 => break,
                Ok(reply) if reply.label == WINDOW_FULL => refused = refused.saturating_add(1),
                _ => std::process::exit(1),
            }
        }
        sent = sent.saturating_add(1);
    }
    std::os::seraph::log!("{TAG}: the resender sent {sent} lines, refused {refused} times");
    std::process::exit(
        if refused > 0
        {
            0
        }
        else
        {
            RESENDER_NEVER_REFUSED
        },
    );
}
