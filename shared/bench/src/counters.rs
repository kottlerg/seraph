// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/counters.rs

//! The counters a benchmark reads around its measured operation.
//!
//! A thread opens its own [`Counters`] after it is pinned to the CPU it
//! measures on, and reads them only there: a counter is a per-CPU register,
//! and no two harts' `cycle` counters are kept in step on riscv64. The handle
//! is neither `Send` nor `Sync`, so it cannot follow the thread's work to
//! another thread. A [`Reading`] holds every column the result line can come
//! to report; [`Counters`] reads the cycle counter alone, and the others read
//! `None`. The hardware event columns are filled by
//! [`crate::EventCounters`] (the `pmu` feature), which reads the cycle
//! counter too.
//!
//! The kernel's `sched-stages` feature calls [`Counters::open`] and
//! [`Counters::read`] from `schedule()`, in kernel mode with interrupts
//! disabled, so neither may make a syscall, allocate, or have any other side
//! effect (shared/bench/README.md § Counters).

use core::marker::PhantomData;

use crate::arch::current;

/// Programmable event counters a [`Reading`] has room for. The bound limits
/// only what one reading reports: a benchmark that counts more events runs
/// once for each group of them.
pub const EVENT_SLOTS: usize = 4;

/// One read of a thread's counters. Subtract two readings on one CPU with
/// [`Reading::since`] to cost the operation between them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reading
{
    /// The cycle counter: `rdtsc` on x86-64, `cycle` on riscv64.
    pub cycles: u64,
    /// Instructions retired; `None` while no counter is opened for them.
    pub instret: Option<u64>,
    /// Programmable event counts; `None` for each slot no event is opened
    /// in.
    pub events: [Option<u64>; EVENT_SLOTS],
}

impl Reading
{
    /// What each counter advanced from `earlier` to this reading, wrapping
    /// as the counters do. A column either reading lacks is `None`.
    #[must_use]
    pub fn since(&self, earlier: &Reading) -> Reading
    {
        self.since_width(earlier, 64)
    }

    /// [`Reading::since`] for instruction and event counters `width` bits
    /// wide, across at most one wrap of each (`pmu::delta`); the cycle
    /// counter wraps at 64 bits.
    #[must_use]
    pub fn since_width(&self, earlier: &Reading, width: u8) -> Reading
    {
        let delta = |now: Option<u64>, then: Option<u64>| Some(pmu::delta(then?, now?, width));
        let mut events = [None; EVENT_SLOTS];
        for ((slot, now), then) in events.iter_mut().zip(self.events).zip(earlier.events)
        {
            *slot = delta(now, then);
        }
        Reading {
            cycles: self.cycles.wrapping_sub(earlier.cycles),
            instret: delta(self.instret, earlier.instret),
            events,
        }
    }
}

/// One thread's open counters.
#[derive(Debug)]
pub struct Counters
{
    /// Neither `Send` nor `Sync`: the counters belong to the CPU the
    /// opening thread is pinned to.
    _cpu_local: PhantomData<*const ()>,
}

impl Counters
{
    /// Open the calling thread's counters. Call it after the thread is pinned
    /// to the CPU it measures on. The cycle counter needs no opening, so this
    /// cannot fail.
    #[must_use]
    pub const fn open() -> Self
    {
        Self {
            _cpu_local: PhantomData,
        }
    }

    /// Read every open counter.
    #[expect(
        clippy::inline_always,
        reason = "the read brackets the measured region, so a call would be measured with it"
    )]
    #[inline(always)]
    #[must_use]
    pub fn read(&self) -> Reading
    {
        Reading {
            cycles: current::cycles(),
            instret: None,
            events: [None; EVENT_SLOTS],
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::{Counters, EVENT_SLOTS, Reading};

    #[test]
    fn reads_report_cycles_only()
    {
        let counters = Counters::open();
        let first = counters.read();
        let second = counters.read();
        assert!(second.cycles >= first.cycles);
        assert_eq!(second.instret, None);
        assert_eq!(second.events, [None; EVENT_SLOTS]);
    }

    // Defect guarded: a counter narrower than 64 bits that wraps between two
    // readings reported as a count near 2^64.
    #[test]
    fn since_width_masks_the_event_columns_to_the_counter_width()
    {
        let width = 48;
        let earlier = Reading {
            cycles: u64::MAX,
            instret: Some(0xFFFF_FFFF_FFFB),
            events: [Some(0xFFFF_FFFF_FFFF), None, Some(2), None],
        };
        let later = Reading {
            cycles: 1,
            instret: Some(6),
            events: [Some(0), None, Some(9), Some(1)],
        };
        assert_eq!(
            later.since_width(&earlier, width),
            Reading {
                cycles: 2,
                instret: Some(11),
                events: [Some(1), None, Some(7), None],
            }
        );
        assert_eq!(later.since(&earlier), later.since_width(&earlier, 64));
    }

    #[test]
    fn since_subtracts_each_column_and_wraps()
    {
        let earlier = Reading {
            cycles: u64::MAX,
            instret: Some(10),
            events: [Some(1), None, Some(5), Some(0)],
        };
        let later = Reading {
            cycles: 4,
            instret: Some(25),
            events: [Some(3), Some(9), None, Some(7)],
        };
        assert_eq!(
            later.since(&earlier),
            Reading {
                cycles: 5,
                instret: Some(15),
                events: [Some(2), None, None, Some(7)],
            }
        );
    }
}
