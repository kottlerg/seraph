// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/cmos/src/lib.rs

//! Host-testable CMOS register snapshot and decode of the cmos-rtc driver.
//!
//! [`snapshot`] takes one consistent reading of the MC146818 time
//! registers through a [`CmosRegs`] accessor, waiting out the
//! update-in-progress window with bounded polls, [`full_year`] joins
//! the two-digit year to the century register the firmware names, and
//! [`decode`] and [`epoch_us`] turn the snapshot into an epoch time. The
//! driver binary (`main.rs`) implements the accessor over the bound CMOS
//! I/O ports.

// Staged roll-out of these two lints: docs/coding-standards.md § Clippy.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// Seconds register.
pub const REG_SECONDS: u8 = 0x00;
/// Minutes register.
pub const REG_MINUTES: u8 = 0x02;
/// Hours register.
pub const REG_HOURS: u8 = 0x04;
/// Day-of-month register.
pub const REG_DAY: u8 = 0x07;
/// Month register.
pub const REG_MONTH: u8 = 0x08;
/// Two-digit year register.
pub const REG_YEAR: u8 = 0x09;
/// Status A register; bit 7 is update-in-progress.
pub const REG_STATUS_A: u8 = 0x0A;
/// Status B register: BCD/binary and 12/24-hour mode bits.
pub const REG_STATUS_B: u8 = 0x0B;
/// The century register an `ipc::device_info_kind::RTC_CENTURY` device-info
/// payload names, from the reply's payload length `byte_len` and its first
/// payload word `first_word`: the payload is one byte, the FADT `CENTURY`
/// index, read through [`century_register`]. `None` for a payload of any
/// other length.
#[must_use]
pub fn century_from_payload(byte_len: u64, first_word: u64) -> Option<u8>
{
    if byte_len != 1
    {
        return None;
    }
    century_register(first_word & 0xFF)
}

/// The CMOS RAM index of a century register the platform names in `index`
/// (the FADT `CENTURY` field), when the
/// driver can read it: 0x0E to 0x7F. 0 names no register. 0x00 to 0x0D are
/// the clock and status registers, which hold no century. 0x80 and up lie
/// past the standard bank the driver's ports reach: written to the index
/// port, bit 7 would disable NMIs on PC chipsets and select another
/// register.
#[must_use]
pub fn century_register(index: u64) -> Option<u8>
{
    u8::try_from(index)
        .ok()
        .filter(|i| (0x0E..=0x7F).contains(i))
}

/// Century the two-digit year is read in when the platform names no century
/// register (the FADT `CENTURY` field is 0) or the register reads as no
/// plausible century: 2000 to 2099. A two-digit year cannot say more.
pub const FALLBACK_CENTURY: u32 = 20;

/// Status A update-in-progress bit.
pub const STATUS_A_UIP: u8 = 0x80;

/// Snapshot attempts before [`snapshot`] gives up. An attempt fails when
/// the update-in-progress bit does not clear within [`UIP_POLL_LIMIT`]
/// polls, rises during the first read, or the two reads disagree. The
/// MC146818 updates once a second and an attempt lasts a few milliseconds, so a
/// working clock fails at most one or two attempts in a row.
pub const MAX_ATTEMPTS: u32 = 16;

/// Status A polls one attempt allows for update-in-progress to clear. The
/// MC146818 holds the bit for at most about 2 ms per update (244 us of
/// warning plus the update itself), and one poll is a port-I/O round trip
/// of at least a microsecond, so a working clock clears well inside the
/// bound; a stuck bit fails the attempt instead of spinning forever.
pub const UIP_POLL_LIMIT: u32 = 10_000;

/// Register read access to the CMOS RTC.
pub trait CmosRegs
{
    /// Read CMOS register `reg`.
    fn read(&mut self, reg: u8) -> u8;
}

/// Raw time-register values from one pass over the CMOS, in the clock's
/// own encoding (BCD or binary, per Status B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmosFields
{
    /// [`REG_SECONDS`].
    pub sec: u8,
    /// [`REG_MINUTES`].
    pub min: u8,
    /// [`REG_HOURS`], PM bit included in 12-hour mode.
    pub hour: u8,
    /// [`REG_DAY`].
    pub day: u8,
    /// [`REG_MONTH`].
    pub month: u8,
    /// [`REG_YEAR`].
    pub year: u8,
    /// The century register the snapshot was asked to read, when it was
    /// asked for one.
    pub century: Option<u8>,
}

fn read_fields(regs: &mut impl CmosRegs, century_reg: Option<u8>) -> CmosFields
{
    CmosFields {
        sec: regs.read(REG_SECONDS),
        min: regs.read(REG_MINUTES),
        hour: regs.read(REG_HOURS),
        day: regs.read(REG_DAY),
        month: regs.read(REG_MONTH),
        year: regs.read(REG_YEAR),
        century: century_reg.map(|reg| regs.read(reg)),
    }
}

fn update_in_progress(regs: &mut impl CmosRegs) -> bool
{
    regs.read(REG_STATUS_A) & STATUS_A_UIP != 0
}

/// Poll Status A until update-in-progress clears; `false` if it is still
/// set after [`UIP_POLL_LIMIT`] polls.
fn wait_update_clear(regs: &mut impl CmosRegs) -> bool
{
    for _ in 0..UIP_POLL_LIMIT
    {
        if !update_in_progress(regs)
        {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Take a consistent snapshot of the CMOS time registers, and of the
/// century register `century_reg` when the platform names one (the FADT
/// `CENTURY` index; `None` reads no century register).
///
/// Each attempt waits (bounded) for update-in-progress to clear, reads the
/// time registers, and re-reads them; it succeeds when update-in-progress
/// stayed clear after the first read and both reads agree. Returns the
/// fields with the Status B value that says how to decode them, or `None`
/// when no attempt in [`MAX_ATTEMPTS`] succeeds (the driver then replies
/// `READ_FAILED`). Every loop is bounded, so a stuck or flapping clock costs
/// a bounded number of register reads.
pub fn snapshot(regs: &mut impl CmosRegs, century_reg: Option<u8>) -> Option<(CmosFields, u8)>
{
    for _ in 0..MAX_ATTEMPTS
    {
        if !wait_update_clear(regs)
        {
            continue;
        }
        let first = read_fields(regs, century_reg);
        if update_in_progress(regs)
        {
            continue;
        }
        let second = read_fields(regs, century_reg);
        if first == second
        {
            return Some((first, regs.read(REG_STATUS_B)));
        }
    }
    None
}

/// The four-digit year of two-digit year `year` (already decoded to
/// binary) and the century register's decoded value `century`, when the
/// platform has one. A century register reading 19 to 99 gives the year's
/// century, so wall time does not wrap at 2100; with no register, or one
/// reading no plausible century, the year falls in [`FALLBACK_CENTURY`].
#[must_use]
pub fn full_year(year: u8, century: Option<u8>) -> u32
{
    let century = century
        .filter(|c| (19..=99).contains(c))
        .map_or(FALLBACK_CENTURY, u32::from);
    // At most 99 * 100 + 255: neither operation saturates.
    century.saturating_mul(100).saturating_add(u32::from(year))
}

// ── Raw → calendar fields ───────────────────────────────────────────────────

/// Status B bit: the time registers hold binary values, not BCD.
pub const STATUS_B_BINARY: u8 = 0x04;
/// Status B bit: the hours register counts 0-23, not 1-12 with a PM bit.
pub const STATUS_B_24H: u8 = 0x02;
/// The PM bit of the hours register in 12-hour mode.
pub const HOUR_PM_BIT: u8 = 0x80;

/// The binary value of BCD byte `v`.
#[must_use]
pub fn bcd_to_bin(v: u8) -> u8
{
    // At most 15 + 15 * 10 = 165: no saturation.
    (v & 0x0F).saturating_add((v >> 4).saturating_mul(10))
}

/// A decoded CMOS reading, each field as the clock gave it after BCD and
/// 12-hour conversion; [`epoch_us`] range-checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calendar
{
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
}

/// Decode a snapshot's `raw` fields under its Status B value `status_b`.
/// The fields are device-supplied and not range-checked here: a PM hour
/// past 11 in 12-hour mode decodes to an hour [`epoch_us`] refuses.
#[must_use]
pub fn decode(raw: CmosFields, status_b: u8) -> Calendar
{
    let binary = status_b & STATUS_B_BINARY != 0;
    let h24 = status_b & STATUS_B_24H != 0;

    let conv = |v: u8| -> u8 { if binary { v } else { bcd_to_bin(v) } };

    let sec = conv(raw.sec);
    let min = conv(raw.min);

    // Hour needs PM-bit handling for 12-hour mode; the PM bit lives in
    // the raw byte and must be masked off before BCD conversion.
    let mut hour_raw = raw.hour;
    let pm = !h24 && (hour_raw & HOUR_PM_BIT != 0);
    hour_raw &= !HOUR_PM_BIT;
    let mut hour = u32::from(conv(hour_raw));
    if !h24
    {
        if hour == 12
        {
            hour = 0;
        }
        if pm
        {
            // The PM bit is masked off, so at most 127 + 12: no saturation.
            hour = hour.saturating_add(12);
        }
    }

    let day = conv(raw.day);
    let month = conv(raw.month);
    let year = full_year(conv(raw.year), raw.century.map(conv));

    Calendar {
        year,
        month: u32::from(month),
        day: u32::from(day),
        hour,
        min: u32::from(min),
        sec: u32::from(sec),
    }
}

// ── Civil-date arithmetic ─────────────────────────────────────────────────

/// Days from 1970-01-01 to `(y, m, d)`, by Howard Hinnant's algorithm, for
/// a year of 1970 or later, a month of 1 to 12 and a day of 1 to 31
/// ([`epoch_us`] checks them). `None` when an intermediate value leaves
/// `u64`, which no date in that range reaches.
fn days_from_civil(y: u32, m: u32, d: u32) -> Option<u64>
{
    // The algorithm's year starts in March.
    let y = u64::from(y).checked_sub(u64::from(m <= 2))?;
    let era = y / 400;
    let yoe = y % 400;
    let m_adj = if m > 2
    {
        m.checked_sub(3)?
    }
    else
    {
        m.checked_add(9)?
    };
    let doy = u64::from(m_adj).checked_mul(153)?.checked_add(2)? / 5;
    let doy = doy.checked_add(u64::from(d))?.checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Per-month max day count. Index 0 is unused; index 2 (February) is
/// the non-leap value — leap years bump it before the check.
const DAYS_IN_MONTH: [u8; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap(year: u32) -> bool
{
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Microseconds from the Unix epoch to calendar time `c`. `None` when a
/// field is out of its range (a month of 0 or past 12, a day of 0 or past
/// its month's last, an hour past 23, a minute or second past 59) or the
/// year is before 1970: the driver then replies `READ_FAILED`.
#[must_use]
pub fn epoch_us(c: Calendar) -> Option<u64>
{
    if c.month == 0 || c.month > 12 || c.day == 0 || c.year < 1970
    {
        return None;
    }
    let mut max_day = u32::from(*DAYS_IN_MONTH.get(usize::try_from(c.month).ok()?)?);
    if c.month == 2 && is_leap(c.year)
    {
        max_day = 29;
    }
    if c.day > max_day || c.hour >= 24 || c.min >= 60 || c.sec >= 60
    {
        return None;
    }
    let days = days_from_civil(c.year, c.month, c.day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(u64::from(c.hour).checked_mul(3600)?)?
        .checked_add(u64::from(c.min).checked_mul(60)?)?
        .checked_add(u64::from(c.sec))?;
    secs.checked_mul(1_000_000)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn calendar(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Calendar
    {
        Calendar {
            year,
            month,
            day,
            hour,
            min,
            sec,
        }
    }

    #[test]
    fn epoch_us_counts_from_the_unix_epoch()
    {
        assert_eq!(epoch_us(calendar(1970, 1, 1, 0, 0, 0)), Some(0));
        // 2000-03-01 12:34:56: 11017 days, past a leap day of a year
        // divisible by 400.
        assert_eq!(
            epoch_us(calendar(2000, 3, 1, 12, 34, 56)),
            Some((11_017 * 86_400 + 12 * 3600 + 34 * 60 + 56) * 1_000_000)
        );
        assert_eq!(
            epoch_us(calendar(2024, 2, 29, 23, 59, 59)),
            Some(1_709_251_199 * 1_000_000)
        );
    }

    #[test]
    fn epoch_us_refuses_fields_out_of_range()
    {
        for c in [
            calendar(1969, 12, 31, 0, 0, 0),
            calendar(2026, 0, 1, 0, 0, 0),
            calendar(2026, 13, 1, 0, 0, 0),
            calendar(2026, 255, 1, 0, 0, 0),
            calendar(2026, 1, 0, 0, 0, 0),
            calendar(2026, 4, 31, 0, 0, 0),
            calendar(2026, 2, 29, 0, 0, 0),
            calendar(2026, 1, 1, 24, 0, 0),
            calendar(2026, 1, 1, 0, 60, 0),
            calendar(2026, 1, 1, 0, 0, 60),
        ]
        {
            assert_eq!(epoch_us(c), None, "{c:?}");
        }
    }

    #[test]
    fn decode_reads_bcd_and_12_hour_fields()
    {
        let raw = CmosFields {
            sec: 0x59,
            min: 0x30,
            hour: HOUR_PM_BIT | 0x12,
            day: 0x31,
            month: 0x12,
            year: 0x26,
            century: Some(0x20),
        };
        // BCD, 12-hour: 12 PM is noon.
        assert_eq!(decode(raw, 0), calendar(2026, 12, 31, 12, 30, 59));
        // 12 AM is midnight.
        let midnight = CmosFields { hour: 0x12, ..raw };
        assert_eq!(decode(midnight, 0).hour, 0);
        // Binary, 24-hour: the bytes are the values, the PM bit is no flag.
        let binary = CmosFields { hour: 23, ..raw };
        assert_eq!(decode(binary, STATUS_B_BINARY | STATUS_B_24H).hour, 23);
        // A non-BCD nibble and the largest masked hour decode out of range,
        // and the epoch refuses them.
        assert_eq!(bcd_to_bin(0xFF), 165);
        let garbage = CmosFields { hour: 0xFF, ..raw };
        let decoded = decode(garbage, STATUS_B_BINARY);
        assert_eq!(decoded.hour, 127 + 12);
        assert_eq!(epoch_us(decoded), None);
    }

    #[test]
    fn century_register_accepts_only_the_standard_bank_past_the_clock()
    {
        assert_eq!(century_register(0x32), Some(0x32));
        assert_eq!(century_register(0x0E), Some(0x0E));
        assert_eq!(century_register(0x7F), Some(0x7F));
        for refused in [0, 0x0A, 0x0D, 0x80, 0xFF, 0x132]
        {
            assert_eq!(century_register(refused), None, "index {refused:#x}");
        }
    }

    #[test]
    fn century_payload_is_one_byte_read_through_the_register_bounds()
    {
        // The payload byte is the low byte of the first payload word.
        assert_eq!(century_from_payload(1, 0x32), Some(0x32));
        assert_eq!(century_from_payload(1, 0xFFFF_FF32), Some(0x32));
        // A register the driver cannot read, or none.
        assert_eq!(century_from_payload(1, 0x80), None);
        assert_eq!(century_from_payload(1, 0), None);
        // A payload of any other length.
        assert_eq!(century_from_payload(0, 0x32), None);
        assert_eq!(century_from_payload(2, 0x32), None);
    }

    #[test]
    fn full_year_takes_the_century_register_past_2099()
    {
        // A clock in 2101 with a century register: no wrap to 2001.
        assert_eq!(full_year(1, Some(21)), 2101);
        assert_eq!(full_year(99, Some(19)), 1999);
    }

    #[test]
    fn full_year_falls_back_without_a_plausible_century_register()
    {
        assert_eq!(full_year(26, None), 2026);
        // A register reading zero (an emulated CMOS that never set it) or
        // garbage is no century.
        assert_eq!(full_year(26, Some(0)), 2026);
        assert_eq!(full_year(26, Some(0xFF)), 2026);
    }

    #[test]
    fn snapshot_reads_the_century_register_the_platform_names()
    {
        // Register 0x48 holds the century here; 0x32 would read 0x11.
        struct CenturyAt(u8);
        impl CmosRegs for CenturyAt
        {
            fn read(&mut self, reg: u8) -> u8
            {
                match reg
                {
                    REG_STATUS_A => 0,
                    r if r == self.0 => 0x21,
                    _ => 0x11,
                }
            }
        }
        let (fields, _) = snapshot(&mut CenturyAt(0x48), Some(0x48)).expect("settles");
        assert_eq!(fields.century, Some(0x21));
        let (fields, _) = snapshot(&mut CenturyAt(0x48), None).expect("settles");
        assert_eq!(fields.century, None);
    }

    /// A simulated clock: Status A reports update-in-progress for the first
    /// `uip_reads` reads of it, the seconds register returns successive
    /// `secs` values (repeating the last), and every read is counted.
    struct FakeCmos
    {
        uip_reads: u64,
        secs: Vec<u8>,
        reads: u64,
    }

    impl CmosRegs for FakeCmos
    {
        fn read(&mut self, reg: u8) -> u8
        {
            self.reads += 1;
            match reg
            {
                REG_STATUS_A if self.uip_reads > 0 =>
                {
                    self.uip_reads -= 1;
                    STATUS_A_UIP
                }
                REG_SECONDS if self.secs.len() > 1 => self.secs.remove(0),
                REG_SECONDS => self.secs[0],
                REG_STATUS_B => 0x02,
                _ => 0x11,
            }
        }
    }

    #[test]
    fn snapshot_gives_up_after_bounded_reads_when_update_in_progress_sticks()
    {
        let mut cmos = FakeCmos {
            uip_reads: u64::MAX,
            secs: vec![0x30],
            reads: 0,
        };
        assert_eq!(snapshot(&mut cmos, None), None);
        assert_eq!(cmos.reads, u64::from(MAX_ATTEMPTS * UIP_POLL_LIMIT));
    }

    #[test]
    fn snapshot_waits_out_an_update_and_returns_agreeing_reads()
    {
        let mut cmos = FakeCmos {
            uip_reads: 3,
            secs: vec![0x30],
            reads: 0,
        };
        let (fields, status_b) = snapshot(&mut cmos, None).expect("clock settles");
        assert_eq!(fields.sec, 0x30);
        assert_eq!(status_b, 0x02);
    }

    #[test]
    fn snapshot_retries_when_the_two_reads_disagree()
    {
        // The seconds register ticks between the first and second read of
        // the first attempt, then holds.
        let mut cmos = FakeCmos {
            uip_reads: 0,
            secs: vec![0x30, 0x31],
            reads: 0,
        };
        let (fields, _) = snapshot(&mut cmos, None).expect("clock settles");
        assert_eq!(fields.sec, 0x31);
    }
}
