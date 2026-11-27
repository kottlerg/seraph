// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/events.rs

//! The hardware event columns of a [`Reading`]: which column each event a
//! benchmark counts fills ([`ColumnPlan`]), and, with the `pmu` feature, the
//! thread's event counters that fill them ([`EventCounters`]).
//!
//! [`Instructions`](PmuEvent::Instructions) fills [`Reading::instret`]; every
//! other event, [`Cycles`](PmuEvent::Cycles) included, fills the next of
//! [`Reading::events`] in the order the events are given. The PMU's
//! `Cycles` counts core clock cycles, where [`Reading::cycles`] is the
//! cycle counter [`crate::Counters`] reads (`rdtsc` on x86-64, `cycle` on
//! riscv64). The access model is docs/capability-model.md § `PmuControl`;
//! shared/bench/README.md § Event counters states the contract.

use pmu::PmuEvent;

#[cfg(feature = "pmu")]
use crate::arch::current;
use crate::counters::{EVENT_SLOTS, Reading};

/// Hardware counters one [`ColumnPlan`] places at most: the instructions
/// column and the event slots.
pub const EVENT_COUNTERS: usize = EVENT_SLOTS + 1;

/// The [`Reading`] column one counted event fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column
{
    /// [`Reading::instret`].
    Instret,
    /// [`Reading::events`] at this index.
    Event(usize),
}

/// The column of each event of a configuration, in the order of its events,
/// which is the order its counters are read in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnPlan
{
    columns: [Column; EVENT_COUNTERS],
    len: usize,
}

impl ColumnPlan
{
    /// The plan for `events`, or `None` when a [`Reading`] cannot hold them:
    /// an event given twice, or more than [`EVENT_SLOTS`] events besides
    /// [`Instructions`](PmuEvent::Instructions).
    #[must_use]
    pub fn new(events: &[PmuEvent]) -> Option<ColumnPlan>
    {
        let mut plan = ColumnPlan {
            columns: [Column::Instret; EVENT_COUNTERS],
            len: 0,
        };
        let mut next_event: usize = 0;
        for (i, &event) in events.iter().enumerate()
        {
            if events.get(..i)?.contains(&event)
            {
                return None;
            }
            let column = if event == PmuEvent::Instructions
            {
                Column::Instret
            }
            else
            {
                let slot = next_event;
                next_event = next_event.saturating_add(1);
                Column::Event(slot)
            };
            if next_event > EVENT_SLOTS
            {
                return None;
            }
            *plan.columns.get_mut(i)? = column;
            plan.len = i.saturating_add(1);
        }
        Some(plan)
    }

    /// The columns, one per event, in the order of the events.
    #[must_use]
    pub fn columns(&self) -> &[Column]
    {
        self.columns.get(..self.len).unwrap_or(&[])
    }

    /// The reading of cycle count `cycles` and of the counter values `raw`,
    /// one per event in the order of the events; a column no event fills is
    /// `None`.
    #[must_use]
    pub fn reading(&self, cycles: u64, raw: &[u64]) -> Reading
    {
        let mut reading = Reading {
            cycles,
            instret: None,
            events: [None; EVENT_SLOTS],
        };
        for (&column, &value) in self.columns().iter().zip(raw)
        {
            match column
            {
                Column::Instret => reading.instret = Some(value),
                Column::Event(slot) =>
                {
                    if let Some(entry) = reading.events.get_mut(slot)
                    {
                        *entry = Some(value);
                    }
                }
            }
        }
        reading
    }
}

/// One thread's open event counters: the cycle counter and up to
/// [`EVENT_COUNTERS`] hardware counters, configured on the CPU the thread is
/// pinned to and readable by that thread alone.
///
/// Neither `Send` nor `Sync`, as [`crate::Counters`] is not.
#[cfg(feature = "pmu")]
#[derive(Debug)]
pub struct EventCounters
{
    pmu: pmu::client::Pmu,
    counters: pmu::client::Counters,
    plan: ColumnPlan,
    thread_cap: u64,
}

#[cfg(feature = "pmu")]
impl EventCounters
{
    /// Configure the calling CPU's counters with `events`, counting `mode`,
    /// through `pmu`, and grant the thread `thread_cap` names, which is the
    /// caller's own, their reads. The caller is pinned to the CPU it measures
    /// on and runs there (shared/pmu/README.md § Client).
    ///
    /// # Errors
    /// `InvalidArgument` when the events do not fit a [`Reading`]
    /// ([`ColumnPlan::new`]), before any syscall; otherwise the error code of
    /// `SYS_PMU_CONFIGURE` or `SYS_PMU_BIND` (`NotSupported` on a CPU with
    /// no counters, or one that does not count an event). A failed bind
    /// releases the configuration.
    pub fn open(
        pmu: pmu::client::Pmu,
        thread_cap: u64,
        events: &[PmuEvent],
        mode: pmu::PmuMode,
    ) -> Result<EventCounters, i64>
    {
        let plan =
            ColumnPlan::new(events).ok_or(syscall_abi::SyscallError::InvalidArgument as i64)?;
        let counters = pmu.configure(events, mode)?;
        if let Err(code) = counters.bind(thread_cap)
        {
            let _ = pmu.release();
            return Err(code);
        }
        Ok(EventCounters {
            pmu,
            counters,
            plan,
            thread_cap,
        })
    }

    /// Read the cycle counter, then every event counter, in that order.
    #[expect(
        clippy::inline_always,
        reason = "the read brackets the measured region, so a call would be measured with it"
    )]
    #[inline(always)]
    #[must_use]
    pub fn read(&self) -> Reading
    {
        let cycles = current::cycles();
        let mut raw = [0u64; EVENT_COUNTERS];
        self.counters.read(&mut raw);
        self.plan.reading(cycles, &raw)
    }

    /// The event counters' width in bits.
    #[must_use]
    pub const fn width(&self) -> u8
    {
        self.counters.width()
    }

    /// What each column advanced from `earlier` to `later`, two readings of
    /// these counters: [`Reading::since_width`] at their width.
    #[must_use]
    pub fn since(&self, later: &Reading, earlier: &Reading) -> Reading
    {
        later.since_width(earlier, self.width())
    }

    /// Revoke the thread's reads and release the CPU's counters, on the CPU
    /// that opened them.
    ///
    /// # Errors
    /// The first error code of `SYS_PMU_BIND` and `SYS_PMU_CONFIGURE`; the
    /// release is made whether or not the unbind succeeds.
    pub fn close(self) -> Result<(), i64>
    {
        let unbound = self.pmu.unbind(self.thread_cap);
        let released = self.pmu.release();
        unbound.and(released)
    }
}

#[cfg(test)]
mod tests
{
    use pmu::PmuEvent;

    use super::{Column, ColumnPlan, EVENT_COUNTERS};
    use crate::counters::{EVENT_SLOTS, Reading};

    // Defect guarded: a counter landing in the wrong column, so a result line
    // reports one event's count under another's name.
    #[test]
    fn instructions_fill_instret_and_the_rest_fill_the_slots_in_order()
    {
        let plan = ColumnPlan::new(&[
            PmuEvent::Cycles,
            PmuEvent::Instructions,
            PmuEvent::DtlbMisses,
            PmuEvent::BranchMisses,
        ])
        .expect("fits");
        assert_eq!(
            plan.columns(),
            [
                Column::Event(0),
                Column::Instret,
                Column::Event(1),
                Column::Event(2),
            ]
        );
        assert_eq!(
            plan.reading(7, &[10, 20, 30, 40]),
            Reading {
                cycles: 7,
                instret: Some(20),
                events: [Some(10), Some(30), Some(40), None],
            }
        );
    }

    #[test]
    fn no_events_read_the_cycle_counter_alone()
    {
        let plan = ColumnPlan::new(&[]).expect("empty");
        assert_eq!(plan.columns(), &[] as &[Column]);
        assert_eq!(
            plan.reading(3, &[]),
            Reading {
                cycles: 3,
                instret: None,
                events: [None; EVENT_SLOTS],
            }
        );
    }

    // The most a reading holds: instructions and every slot.
    #[test]
    fn instructions_and_every_slot_fit()
    {
        let events = [
            PmuEvent::LlcMisses,
            PmuEvent::LlcReferences,
            PmuEvent::Instructions,
            PmuEvent::BranchInstructions,
            PmuEvent::ItlbMisses,
        ];
        assert_eq!(events.len(), EVENT_COUNTERS);
        let plan = ColumnPlan::new(&events).expect("fits");
        assert_eq!(plan.columns().get(2), Some(&Column::Instret));
        assert_eq!(plan.columns().last(), Some(&Column::Event(EVENT_SLOTS - 1)));
    }

    #[test]
    fn more_events_than_slots_or_a_repeat_do_not_fit()
    {
        assert_eq!(
            ColumnPlan::new(&[
                PmuEvent::Cycles,
                PmuEvent::LlcMisses,
                PmuEvent::LlcReferences,
                PmuEvent::BranchInstructions,
                PmuEvent::ItlbMisses,
            ]),
            None
        );
        assert_eq!(
            ColumnPlan::new(&[PmuEvent::Instructions, PmuEvent::Instructions]),
            None
        );
        assert_eq!(
            ColumnPlan::new(&[PmuEvent::Cycles, PmuEvent::BranchMisses, PmuEvent::Cycles]),
            None
        );
    }
}
