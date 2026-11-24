// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/timed.rs

//! `timed` service surface: `std::time::SystemTime::now()` end-to-end
//! through the per-process `service_registry_cap` → svcmgr
//! `QUERY_ENDPOINT` → timed `GET_WALL_TIME` → kernel monotonic + offset.
//!
//! The RTC restart phase kills the RTC driver through the debug authority,
//! with a fault at an unmapped address, and waits for devmgr's restart of
//! it, which devmgr serves at the `rtc` class's next ordinal
//! (services/devmgr/docs/responsibilities.md § Driver Restart). It then kills
//! timed in the same way, and svcmgr restarts it under its recipe's
//! `restart = on_failure`. The new timed resolves the RTC after the
//! driver's restart, so it must find the new instance past the withdrawn
//! ordinal: `SystemTime::now()` must give a time again within a bound, where
//! a timed that resolved the withdrawn ordinal answers
//! `WALL_CLOCK_UNAVAILABLE` for the boot and `now()` gives `UNIX_EPOCH`.
//!
//! The RTC create-retry phase before it, which runs when the `memhog` fixture
//! is staged, has devmgr's restart of the RTC driver made while memory is
//! critical, so procmgr refuses its create, and requires devmgr to retry the
//! create until the driver starts
//! (services/devmgr/docs/responsibilities.md § Create retry). It attaches to
//! devmgr and stops its main thread, which runs every restart, kills the RTC
//! driver and waits until procmgr no longer lists it, so the driver's frames
//! are free before the fill. Through `oom::critical_window`, the fixture then
//! fills the pool down to the growth floor, and once the level reads
//! `CRITICAL` the phase starts devmgr's main thread again: devmgr withdraws
//! the dead driver, admits its restart, and makes its create while the
//! fixture holds every page a driver outside the system reserve could take,
//! so procmgr refuses it. The phase requires devmgr's line for the refusal
//! and its first retry, stamped after the kill, then, once the fixture is
//! stopped and the level falls, devmgr serving the retried driver at the
//! `rtc` class's next ordinal, so the next phase's kill of it is a served
//! driver's death, which devmgr restarts, and devmgr's line for the retry that
//! started it. Without the retry devmgr logs the restart as
//! failed and leaves the record with no driver, and the phase fails. Its
//! restart leaves timed holding the withdrawn ordinal, which the RTC restart
//! phase's kill of timed resolves again.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

use crate::arch::current::RTC_DRIVER_NAME;
use crate::bootstrap::Caps;
use crate::ipc_util::time::epoch_to_ymdhms;
use crate::runner::Phase;

// 2024-01-01 00:00:00 UTC = 1 704 067 200 s.
const SYSTEM_TIME_AFTER_2024_SECS: u64 = 1_704_067_200;
// 2100-01-01 00:00:00 UTC = 4 102 444 800 s. Sanity ceiling: QEMU's century
// register reads zero, and the cmos driver's fallback century of 20 keeps the
// year below 2100.
const SYSTEM_TIME_BEFORE_2100_SECS: u64 = 4_102_444_800;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "system_time",
            run: system_time_phase,
        },
        Phase {
            name: "rtc_create_retry",
            run: rtc_create_retry_phase,
        },
        Phase {
            name: "timed_rtc_restart",
            run: timed_rtc_restart_phase,
        },
    ]
}

/// timed's process name: the first word of its recipe's `argv`.
const TIMED_NAME: &[u8] = b"timed";

/// How long the RTC restart phase waits, at most, for each restart: the RTC
/// driver's, and timed's answer with a time.
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the RTC restart phase waits between looks.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub fn system_time_phase(_: &Caps)
{
    fn sample() -> (Instant, SystemTime, Instant)
    {
        let i_pre = Instant::now();
        let t = SystemTime::now();
        let i_post = Instant::now();
        (i_pre, t, i_post)
    }

    let (i_pre0, t0, i_post0) = sample();
    let since_epoch = t0
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime::now must be at or after UNIX_EPOCH");
    // Every machine the harness boots has an RTC that a platform device
    // record describes (the CMOS RTC on x86-64, the goldfish RTC on riscv64),
    // and devmgr settles that driver's bind pass before it receives timed's
    // query: a UNIX_EPOCH reply means that record or its bind is missing.
    assert!(
        since_epoch != Duration::ZERO,
        "SystemTime returned UNIX_EPOCH: timed has no wall clock, so no RTC \
         driver is bound to the machine's RTC record",
    );

    let secs = since_epoch.as_secs();
    assert!(
        secs >= SYSTEM_TIME_AFTER_2024_SECS,
        "SystemTime returned {secs}s, before 2024-01-01 — \
         timed offset miswired or RTC clock not running",
    );
    assert!(
        secs < SYSTEM_TIME_BEFORE_2100_SECS,
        "SystemTime returned {secs}s, after 2100-01-01 — overflow or junk read",
    );

    let target = Duration::from_millis(50);
    while i_post0.elapsed() < target
    {
        core::hint::spin_loop();
    }

    let (i_pre1, t1, i_post1) = sample();
    let sys_delta = t1
        .duration_since(t0)
        .expect("SystemTime monotonicity (wall clock did not run backwards)");

    let mono_min = i_pre1.duration_since(i_post0);
    let mono_max = i_post1.duration_since(i_pre0);

    // Wall (SystemTime, served by `timed`) and monotonic (Instant) both derive
    // from the kernel `ElapsedUs` counter, but `timed` reads it across an IPC
    // round-trip; under SMP oversubscription host descheduling lands that read
    // at a different point than the local `Instant` reads, so the wall delta
    // skews from the tight bracket (~2 ms on a 50 ms window observed under
    // contention). Compare with a coarse slack of half the monotonic interval
    // (10 ms floor for short windows): it admits a wall delta within ~±50% of
    // the elapsed interval — enough to absorb the skew, while still failing a
    // stalled clock or one misrated by more than ~50%. Offset wiring is covered
    // by the 2024/2100 bounds above; the lower bound is additive
    // (`sys_delta + slack >= mono_min`) so it cannot underflow Duration
    // subtraction.
    let slack = mono_max
        .checked_div(2)
        .expect("monotonic interval halved")
        .max(Duration::from_millis(10));
    assert!(
        sys_delta
            .checked_add(slack)
            .expect("SystemTime delta plus slack overflowed")
            >= mono_min
            && sys_delta
                <= mono_max
                    .checked_add(slack)
                    .expect("monotonic interval plus slack overflowed"),
        "SystemTime delta {sys_delta:?} outside Instant bracket \
         [{mono_min:?}, {mono_max:?}] ±{slack:?} — clocks not tracking",
    );

    let (y, mo, dd, hh, mm, ss) = epoch_to_ymdhms(secs);
    std::os::seraph::log!(
        "SystemTime phase passed ({y:04}-{mo:02}-{dd:02}T{hh:02}:{mm:02}:{ss:02}Z, sys_delta={sys_delta:?}, mono_bounds=[{mono_min:?}, {mono_max:?}], slack={slack:?})"
    );
}

/// devmgr's process name in `LIST_PROCESSES`: init creates it from its boot
/// module.
const DEVMGR_NAME: &[u8] = b"devmgr";

/// How long the RTC create-retry phase holds memory critical when no oomd
/// stops the `memhog` fixture, and svctest stops it: past devmgr's first two
/// retries (1 s and 3 s after the refusal). A test wait bound.
const RETRY_HOLD: Duration = Duration::from_secs(5);

/// How long the RTC create-retry phase waits for each of devmgr's lines and
/// for the retried driver: past devmgr's whole retry schedule (63 s,
/// `CREATE_RETRY_LIMIT` in services/devmgr/firmware/src/restart.rs) and a
/// settle bound. A test wait bound.
const RETRY_TIMEOUT: Duration = Duration::from_secs(90);

/// Have devmgr's restart of the RTC driver refused while memory is critical,
/// and require devmgr to retry its create until the driver starts (see the
/// module documentation).
pub fn rtc_create_retry_phase(caps: &Caps)
{
    let phase = "rtc_create_retry";
    if !super::fixtures::staged(svctest_fixtures::Fixture::Memhog)
    {
        super::fixtures::skip(phase, svctest_fixtures::Fixture::Memhog);
        return;
    }
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{phase}: no debug authority");
    assert_ne!(caps.logd_query, 0, "{phase}: no logd.query seed");
    // devmgr's lines name the driver by its declared name, the last part of
    // its install path.
    let driver = RTC_DRIVER_NAME
        .rsplit(|&b| b == b'/')
        .next()
        .unwrap_or(RTC_DRIVER_NAME);

    assert_ne!(caps.rtc_class, 0, "{phase}: no devmgr.class.rtc seed");
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let (ordinal, served) = unsafe { ipc::first_device_from(caps.rtc_class, 0, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: devmgr serves no RTC driver ({e:?})"));
    let _ = syscall::cap_delete(served);
    let devmgr = super::crash::badge_named(authority, DEVMGR_NAME)
        .unwrap_or_else(|| panic!("{phase}: LIST_PROCESSES lists no devmgr"));
    let rtc = super::crash::badge_named(authority, RTC_DRIVER_NAME)
        .unwrap_or_else(|| panic!("{phase}: LIST_PROCESSES lists no RTC driver"));
    let threads = attach(authority, devmgr, phase);
    let control = *threads
        .first()
        .unwrap_or_else(|| panic!("{phase}: the devmgr attach returned no main thread"));
    syscall::thread_stop(control)
        .unwrap_or_else(|e| panic!("{phase}: stopping devmgr's main thread ({e})"));
    let killed_us = super::oom::elapsed_us();
    super::logd_sinks::kill(authority, rtc, "RTC");
    super::logd_sinks::await_gone(authority, rtc, RTC_DRIVER_NAME, "RTC");
    let mut resumed = Ok(());
    super::oom::critical_window(caps, phase, RETRY_HOLD, || {
        // The driver's death post waits on devmgr's queue: the restart it
        // admits makes its create now, with the pool at the growth floor.
        resumed = syscall::thread_start(control);
    });
    resumed.unwrap_or_else(|e| panic!("{phase}: starting devmgr's main thread ({e})"));
    detach(authority, devmgr, threads, phase);

    let refused_us = await_line(
        caps.logd_query,
        &[driver, b": create refused (", b"); retry 1 of "],
        killed_us,
        phase,
    );
    await_served(caps.rtc_class, ordinal.saturating_add(1), phase);
    assert!(
        super::crash::badge_named(authority, RTC_DRIVER_NAME).is_some_and(|b| b != rtc),
        "{phase}: devmgr serves an RTC driver LIST_PROCESSES does not list as a new process"
    );
    let retried_us = await_line(
        caps.logd_query,
        &[driver, b": create retry "],
        refused_us,
        phase,
    );
    let took = retried_us.saturating_sub(refused_us) / 1000;
    std::os::seraph::log!(
        "rtc_create_retry phase passed (the RTC driver's restart refused while memory was \
         critical; its first create retry {took} ms later)"
    );
}

/// Wait until devmgr serves a driver at the `rtc` class's ordinal `next`,
/// through `class`, the class's SEND, for up to [`RETRY_TIMEOUT`]: the
/// retried driver, which the next phase kills at once, and whose death devmgr
/// restarts only once its batch has settled and served it
/// (services/devmgr/docs/responsibilities.md § When a driver restarts). A
/// listed driver can still be in its batch. The query waits while a retry's
/// settle runs and answers `NO_DEVICE` between the retries.
fn await_served(class: u64, next: u64, phase: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let start_at = Instant::now();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        match unsafe { ipc::query_device(class, next, ipc_buf) }
        {
            Ok(served) =>
            {
                let _ = syscall::cap_delete(served);
                return;
            }
            Err(ipc::ClassCallError::Refused(ipc::devmgr_errors::NO_DEVICE)) =>
            {}
            Err(e) => panic!("{phase}: querying the RTC class at ordinal {next} ({e:?})"),
        }
        assert!(
            start_at.elapsed() < RETRY_TIMEOUT,
            "{phase}: devmgr's retries did not serve the RTC driver at ordinal {next}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Attach to devmgr, `process`: the caps of its threads, main thread first.
fn attach(authority: u64, process: u64, phase: &str) -> Vec<u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: ATTACH_PROCESS of devmgr failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{phase}: ATTACH_PROCESS of devmgr refused ({:#x})",
        reply.label
    );
    reply.caps().to_vec()
}

/// Let go of devmgr, `process` (`DETACH_PROCESS`), and delete its thread
/// caps.
fn detach(authority: u64, process: u64, threads: Vec<u64>, phase: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
        .word(0, process)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: DETACH_PROCESS of devmgr failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{phase}: DETACH_PROCESS of devmgr refused ({:#x})",
        reply.label
    );
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// The stamp of the oldest entry of logd's history, through `query`, that is
/// stamped at or after `after_us` and holds every one of `parts`, read every
/// [`POLL_INTERVAL`] until one is there, for up to [`RETRY_TIMEOUT`].
fn await_line(query: u64, parts: &[&[u8]], after_us: u64, phase: &str) -> u64
{
    let holds = |bytes: &[u8]| {
        parts
            .iter()
            .all(|part| bytes.windows(part.len()).any(|w| w == *part))
    };
    let start = Instant::now();
    loop
    {
        // Newest first: the last match read is the oldest.
        let oldest = super::procmgr::logd_history_with(query, None, |entry| {
            (entry.us >= after_us && holds(entry.bytes)).then_some(entry.us)
        })
        .into_iter()
        .rev()
        .flatten()
        .next();
        if let Some(us) = oldest
        {
            return us;
        }
        let shown: Vec<_> = parts.iter().map(|p| String::from_utf8_lossy(p)).collect();
        assert!(
            start.elapsed() < RETRY_TIMEOUT,
            "{phase}: logd's history holds no line with {shown:?} stamped after {after_us} us"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill the RTC driver, then timed, and require the restarted timed to serve
/// the wall clock (see the module documentation).
pub fn timed_rtc_restart_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "timed_rtc_restart: no debug authority");

    let rtc = super::crash::badge_named(authority, RTC_DRIVER_NAME)
        .expect("timed_rtc_restart: LIST_PROCESSES lists no RTC driver");
    super::logd_sinks::kill(authority, rtc, "RTC");
    super::logd_sinks::await_gone(authority, rtc, RTC_DRIVER_NAME, "RTC");
    let start_at = Instant::now();
    while super::crash::badge_named(authority, RTC_DRIVER_NAME).is_none_or(|b| b == rtc)
    {
        assert!(
            start_at.elapsed() < RESTART_TIMEOUT,
            "timed_rtc_restart: devmgr did not restart the RTC driver"
        );
        std::thread::sleep(POLL_INTERVAL);
    }

    let timed = super::crash::badge_named(authority, TIMED_NAME)
        .expect("timed_rtc_restart: LIST_PROCESSES lists no timed");
    super::logd_sinks::kill(authority, timed, "timed");
    super::logd_sinks::await_gone(authority, timed, TIMED_NAME, "timed");

    // The calls queue on timed's endpoint, which svcmgr keeps across the
    // restart, until the new instance receives on it.
    let start_at = Instant::now();
    let secs = loop
    {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime::now must be at or after UNIX_EPOCH")
            .as_secs();
        if secs != 0
        {
            break secs;
        }
        assert!(
            start_at.elapsed() < RESTART_TIMEOUT,
            "timed_rtc_restart: the timed started after the RTC driver's restart has no wall \
             clock (SystemTime::now gives UNIX_EPOCH)"
        );
        std::thread::sleep(POLL_INTERVAL);
    };
    assert!(
        (SYSTEM_TIME_AFTER_2024_SECS..SYSTEM_TIME_BEFORE_2100_SECS).contains(&secs),
        "timed_rtc_restart: the restarted timed gives {secs}s, outside 2024 to 2100"
    );
    std::os::seraph::log!(
        "timed_rtc_restart phase passed (RTC driver and timed restarted, wall clock {secs}s)"
    );
}
