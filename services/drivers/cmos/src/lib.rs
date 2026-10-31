// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/cmos/src/lib.rs

//! Host-testable CMOS register snapshot of the cmos-rtc driver.
//!
//! [`snapshot`] takes one consistent reading of the MC146818 time
//! registers through a [`CmosRegs`] accessor, waiting out the
//! update-in-progress window with bounded polls, and [`full_year`] joins
//! the two-digit year to the century register the firmware names. The
//! driver binary (`main.rs`) implements the accessor over the bound CMOS
//! I/O ports and decodes the snapshot into an epoch time.

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
    century * 100 + u32::from(year)
}

#[cfg(test)]
mod tests
{
    use super::*;

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
