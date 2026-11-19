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

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
