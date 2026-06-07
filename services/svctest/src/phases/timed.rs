// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! `timed` service surface: `std::time::SystemTime::now()` end-to-end
//! through the per-process `service_registry_cap` → svcmgr
//! `QUERY_ENDPOINT` → timed `GET_WALL_TIME` → kernel monotonic + offset.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bootstrap::Caps;
use crate::ipc_util::time::epoch_to_ymdhms;
use crate::runner::Phase;

// 2024-01-01 00:00:00 UTC = 1 704 067 200 s.
const SYSTEM_TIME_AFTER_2024_SECS: u64 = 1_704_067_200;
// 2100-01-01 00:00:00 UTC = 4 102 444 800 s. Sanity ceiling.
const SYSTEM_TIME_BEFORE_2100_SECS: u64 = 4_102_444_800;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "system_time",
        run: system_time_phase,
    }]
}

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
    if since_epoch == Duration::ZERO
    {
        std::os::seraph::log!("SystemTime phase skipped: timed unavailable (UNIX_EPOCH reply)");
        return;
    }

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
    let slack = (mono_max / 2).max(Duration::from_millis(10));
    assert!(
        sys_delta + slack >= mono_min && sys_delta <= mono_max + slack,
        "SystemTime delta {sys_delta:?} outside Instant bracket \
         [{mono_min:?}, {mono_max:?}] ±{slack:?} — clocks not tracking",
    );

    let (y, mo, dd, hh, mm, ss) = epoch_to_ymdhms(secs);
    std::os::seraph::log!(
        "SystemTime phase passed ({y:04}-{mo:02}-{dd:02}T{hh:02}:{mm:02}:{ss:02}Z, sys_delta={sys_delta:?}, mono_bounds=[{mono_min:?}, {mono_max:?}], slack={slack:?})"
    );
}
