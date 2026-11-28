// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/wall.rs

//! Wall time: an RFC 3339 UTC time from microseconds since the Unix epoch,
//! as a sink shows an entry's wall time and logd's notice of the wall clock
//! states it ([sinks.md](../../docs/sinks.md) § Wall time).

use core::fmt::Write;

use crate::BoundedStr;
use crate::prefix::write_decimal;

/// The last microsecond an RFC 3339 time can show, its year having four
/// digits: 9999-12-31T23:59:59.999999Z.
pub const WALL_MAX_US: u64 = 253_402_300_800_000_000 - 1;

/// Bytes of an RFC 3339 time with microseconds,
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
pub const RFC3339_US_LEN: usize = 27;

/// How finely [`write_rfc3339`] writes a time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Precision
{
    /// To the second, `YYYY-MM-DDTHH:MM:SSZ`.
    Seconds,
    /// To the microsecond, `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
    Micros,
}

/// Microseconds in a day.
const DAY_US: u64 = 86_400_000_000;

/// The civil date, (year, month, day), of `days` days after 1970-01-01, in
/// the proleptic Gregorian calendar (Howard Hinnant's `civil_from_days`,
/// for days on or after the epoch).
fn civil_from_days(days: u64) -> (u64, u64, u64)
{
    // Days since 0000-03-01, the start of a 400-year era whose leap day ends
    // each year.
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if mp < 10
    {
        mp.saturating_add(3)
    }
    else
    {
        mp.saturating_sub(9)
    };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(month <= 2));
    (year, month, day)
}

/// Write `wall_us`, microseconds since 1970-01-01T00:00:00Z, as an RFC 3339
/// UTC time through `out` at `precision`: `YYYY-MM-DDTHH:MM:SS`, then
/// `.ffffff` for [`Precision::Micros`], then `Z`. Writes nothing and returns `false` for a time past
/// [`WALL_MAX_US`], which RFC 3339's four-digit year cannot show.
pub fn write_rfc3339(wall_us: u64, precision: Precision, out: &mut impl FnMut(u8)) -> bool
{
    if wall_us > WALL_MAX_US
    {
        return false;
    }
    let (year, month, day) = civil_from_days(wall_us / DAY_US);
    let of_day = wall_us % DAY_US;
    let secs = of_day / 1_000_000;
    write_decimal(year, 4, b'0', out);
    out(b'-');
    write_decimal(month, 2, b'0', out);
    out(b'-');
    write_decimal(day, 2, b'0', out);
    out(b'T');
    write_decimal(secs / 3600, 2, b'0', out);
    out(b':');
    write_decimal(secs / 60 % 60, 2, b'0', out);
    out(b':');
    write_decimal(secs % 60, 2, b'0', out);
    if precision == Precision::Micros
    {
        out(b'.');
        write_decimal(of_day % 1_000_000, 6, b'0', out);
    }
    out(b'Z');
    true
}

/// The text of logd's notice that the wall clock is known: the wall time
/// `wall_us` to the second and the uptime `uptime_us` of the same instant,
/// so every uptime in a capture converts
/// (`wall clock 2026-11-25T09:01:11Z at uptime 3.201440`). A wall time RFC
/// 3339 cannot show is given as its microseconds since the epoch
/// (`wall clock 253402300800000000 us at uptime 3.201440`).
#[must_use]
pub fn wall_clock_text(wall_us: u64, uptime_us: u64) -> BoundedStr<64>
{
    let mut time = [0u8; RFC3339_US_LEN];
    let mut len = 0usize;
    write_rfc3339(wall_us, Precision::Seconds, &mut |b| {
        if let Some(slot) = time.get_mut(len)
        {
            *slot = b;
            len = len.saturating_add(1);
        }
    });
    let time = core::str::from_utf8(time.get(..len).unwrap_or_default()).unwrap_or_default();
    let mut text = BoundedStr::new();
    let _ = if time.is_empty()
    {
        write!(text, "wall clock {wall_us} us")
    }
    else
    {
        write!(text, "wall clock {time}")
    };
    let _ = write!(
        text,
        " at uptime {}.{:06}",
        uptime_us / 1_000_000,
        uptime_us % 1_000_000
    );
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn rfc3339(wall_us: u64, precision: Precision) -> Option<String>
    {
        let mut out = Vec::new();
        write_rfc3339(wall_us, precision, &mut |b| out.push(b))
            .then(|| String::from_utf8(out).unwrap())
    }

    /// Microseconds since the epoch of the time of day `h:m:s` and `frac`
    /// microseconds, `days` days after 1970-01-01.
    fn us(days: u64, h: u64, m: u64, s: u64, frac: u64) -> u64
    {
        ((days * 86_400 + h * 3600 + m * 60 + s) * 1_000_000) + frac
    }

    // Defect caught: a date off by a day at a month's or a leap year's edge,
    // a century year taken as leap (or 2000 as not), a field not zero-padded,
    // or the microseconds misplaced, so a capture's wall times are wrong.
    #[test]
    fn a_wall_time_is_written_as_rfc3339_utc()
    {
        assert_eq!(
            rfc3339(0, Precision::Micros).as_deref(),
            Some("1970-01-01T00:00:00.000000Z")
        );
        assert_eq!(
            rfc3339(0, Precision::Seconds).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        // 2000-02-29: 2000 is a leap year though a century.
        assert_eq!(
            rfc3339(us(11_016, 23, 59, 59, 999_999), Precision::Micros).as_deref(),
            Some("2000-02-29T23:59:59.999999Z")
        );
        assert_eq!(
            rfc3339(us(11_017, 0, 0, 0, 0), Precision::Seconds).as_deref(),
            Some("2000-03-01T00:00:00Z")
        );
        // 2100-02-28 is followed by 2100-03-01: 2100 is not a leap year.
        assert_eq!(
            rfc3339(us(47_540, 0, 0, 0, 0), Precision::Seconds).as_deref(),
            Some("2100-02-28T00:00:00Z")
        );
        assert_eq!(
            rfc3339(us(47_541, 0, 0, 0, 0), Precision::Seconds).as_deref(),
            Some("2100-03-01T00:00:00Z")
        );
        assert_eq!(
            rfc3339(us(20_417, 9, 1, 11, 42), Precision::Micros).as_deref(),
            Some("2025-11-25T09:01:11.000042Z")
        );
        assert_eq!(
            rfc3339(us(20_453, 23, 0, 5, 0), Precision::Seconds).as_deref(),
            Some("2025-12-31T23:00:05Z")
        );
        assert_eq!(
            rfc3339(us(20_454, 0, 0, 0, 0), Precision::Seconds).as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    // Defect caught: a time past the four-digit year written as a five-digit
    // year, which is not RFC 3339, or the last one RFC 3339 shows refused.
    #[test]
    fn a_wall_time_past_year_9999_is_not_written()
    {
        assert_eq!(
            rfc3339(WALL_MAX_US, Precision::Micros).as_deref(),
            Some("9999-12-31T23:59:59.999999Z")
        );
        assert_eq!(
            rfc3339(WALL_MAX_US, Precision::Micros).map(|s| s.len()),
            Some(RFC3339_US_LEN)
        );
        assert_eq!(rfc3339(WALL_MAX_US + 1, Precision::Micros), None);
        assert_eq!(rfc3339(u64::MAX, Precision::Seconds), None);
    }

    // Defect caught: a notice whose uptime drops its leading zeros of
    // microseconds or whose wall time carries microseconds, against the
    // documented line.
    #[test]
    fn the_wall_clock_notice_states_the_wall_time_and_its_uptime()
    {
        assert_eq!(
            wall_clock_text(us(20_417, 9, 1, 11, 500_000), 3_001_440).as_str(),
            "wall clock 2025-11-25T09:01:11Z at uptime 3.001440"
        );
        assert_eq!(
            wall_clock_text(u64::MAX, 0).as_str(),
            "wall clock 18446744073709551615 us at uptime 0.000000"
        );
    }
}
