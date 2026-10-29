// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/cmos/src/lib.rs

//! Host-testable CMOS register snapshot of the cmos-rtc driver.
//!
//! [`snapshot`] takes one consistent reading of the MC146818 time
//! registers through a [`CmosRegs`] accessor, waiting out the
//! update-in-progress window with bounded polls. The driver binary
//! (`main.rs`) implements the accessor over the bound CMOS I/O ports and
//! decodes the snapshot into an epoch time.

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
/// Century register (zero on QEMU).
pub const REG_CENTURY: u8 = 0x32;

/// Status A update-in-progress bit.
pub const STATUS_A_UIP: u8 = 0x80;

/// Snapshot attempts before [`snapshot`] gives up. An attempt fails when
/// the update-in-progress bit does not clear within [`UIP_POLL_LIMIT`]
/// polls, rises during the first read, or the two reads disagree.
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
    /// [`REG_CENTURY`].
    pub century: u8,
}

fn read_fields(regs: &mut impl CmosRegs) -> CmosFields
{
    CmosFields {
        sec: regs.read(REG_SECONDS),
        min: regs.read(REG_MINUTES),
        hour: regs.read(REG_HOURS),
        day: regs.read(REG_DAY),
        month: regs.read(REG_MONTH),
        year: regs.read(REG_YEAR),
        century: regs.read(REG_CENTURY),
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

/// Take a consistent snapshot of the CMOS time registers.
///
/// Each attempt waits (bounded) for update-in-progress to clear, reads the
/// time registers, and re-reads them; it succeeds when update-in-progress
/// stayed clear after the first read and both reads agree. Returns the
/// fields with the Status B value that says how to decode them, or `None`
/// when no attempt in [`MAX_ATTEMPTS`] succeeds (the driver then replies
/// `READ_FAILED`). Every loop is bounded, so a stuck or flapping clock costs
/// a bounded number of register reads.
pub fn snapshot(regs: &mut impl CmosRegs) -> Option<(CmosFields, u8)>
{
    for _ in 0..MAX_ATTEMPTS
    {
        if !wait_update_clear(regs)
        {
            continue;
        }
        let first = read_fields(regs);
        if update_in_progress(regs)
        {
            continue;
        }
        let second = read_fields(regs);
        if first == second
        {
            return Some((first, regs.read(REG_STATUS_B)));
        }
    }
    None
}

#[cfg(test)]
mod tests
{
    use super::*;

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
        assert_eq!(snapshot(&mut cmos), None);
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
        let (fields, status_b) = snapshot(&mut cmos).expect("clock settles");
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
        let (fields, _) = snapshot(&mut cmos).expect("clock settles");
        assert_eq!(fields.sec, 0x31);
    }
}
