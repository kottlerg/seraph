// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/ipc_util/time.rs

//! Time-conversion helpers used by phases that decode wall-clock values.

/// Convert seconds since the Unix epoch to `(year, month, day, hh, mm, ss)`.
/// Civil-from-days algorithm (Howard Hinnant, public domain); branch-free
/// for years ≥ 0.
///
/// # Panics
///
/// Panics when the year does not fit `u32` (a year past 4.29e9), which no
/// wall clock reports: the caller is a test, so that clock fails it.
pub fn epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32)
{
    civil_from_secs(secs).expect("wall-clock seconds past the u32 year range")
}

/// [`epoch_to_ymdhms`], `None` when an intermediate overflows. Every step but
/// the era's year term is bounded by the era's 146 097 days, so only an
/// out-of-range year reaches `None`.
// cast_possible_truncation: the second of the day (< 86 400) and the day of
// the era (< 146 097) fit u32.
#[allow(clippy::cast_possible_truncation)]
fn civil_from_secs(secs: u64) -> Option<(u32, u32, u32, u32, u32, u32)>
{
    let days = secs / 86_400;
    let sod = (secs % 86_400) as u32;
    let hh = sod / 3_600;
    let mm = (sod / 60) % 60;
    let ss = sod % 60;

    // z is days since 0000-03-01; valid for any post-epoch input.
    let z = days.checked_add(719_468)?;
    let era = u32::try_from(z / 146_097).ok()?;
    let doe = (z % 146_097) as u32;
    let yoe = doe
        .checked_sub(doe / 1_460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let y = era.checked_mul(400)?.checked_add(yoe)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let month = if mp < 10
    {
        mp.checked_add(3)?
    }
    else
    {
        mp.checked_sub(9)?
    };
    let year = if month <= 2 { y.checked_add(1)? } else { y };
    Some((year, month, d, hh, mm, ss))
}
