// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Time-conversion helpers used by phases that decode wall-clock values.

/// Convert seconds since the Unix epoch to `(year, month, day, hh, mm, ss)`.
/// Civil-from-days algorithm (Howard Hinnant, public domain); branch-free
/// for years ≥ 0.
#[allow(clippy::cast_possible_truncation)]
pub fn epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32)
{
    let days = secs / 86_400;
    let sod = (secs % 86_400) as u32;
    let hh = sod / 3_600;
    let mm = (sod / 60) % 60;
    let ss = sod % 60;

    // z is days since 0000-03-01; valid for any post-epoch input.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + (era as u32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, d, hh, mm, ss)
}
