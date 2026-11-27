// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/pmu/src/lib.rs

//! Hardware performance counters: the portable events, the packing of the
//! `PmuControl` syscalls' registers, the per-vendor decode and event tables the
//! kernel programs counters from, and, with the `client` feature, the user API
//! a measuring thread reads its CPU's counters through.
//!
//! Everything but [`client`] is pure logic, shared by the kernel and its
//! callers and host-tested. The access model is docs/capability-model.md
//! § `PmuControl`; the syscalls are core/kernel/docs/syscalls.md
//! § `SYS_PMU_INFO` (79) onwards.

#![no_std]

pub mod amd;
pub mod intel;
pub mod riscv;

#[cfg(feature = "client")]
pub mod client;

use syscall_abi::{
    PMU_CONFIGURE_MAX, PMU_ENTRY_BITS, PMU_ENTRY_MASK, PMU_EVENT_BRANCH_INSTRUCTIONS,
    PMU_EVENT_BRANCH_MISSES, PMU_EVENT_COUNT, PMU_EVENT_CYCLES, PMU_EVENT_DTLB_MISSES,
    PMU_EVENT_INSTRUCTIONS, PMU_EVENT_ITLB_MISSES, PMU_EVENT_LLC_MISSES, PMU_EVENT_LLC_REFERENCES,
    PMU_INFO_COUNTERS_MASK, PMU_INFO_COUNTERS_SHIFT, PMU_INFO_EVENTS_MASK, PMU_INFO_EVENTS_SHIFT,
    PMU_INFO_WIDTH_MASK, PMU_INFO_WIDTH_SHIFT, PMU_MODE_KERNEL, PMU_MODE_USER,
};

/// A portable event: what a counter counts, which the kernel maps to each
/// CPU's own encoding. [`Cycles`](Self::Cycles) and
/// [`Instructions`](Self::Instructions) are counted wherever a PMU exists; the
/// others only where the CPU counts them, which [`Info::supports`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PmuEvent
{
    /// Core clock cycles.
    Cycles = PMU_EVENT_CYCLES,
    /// Instructions retired.
    Instructions = PMU_EVENT_INSTRUCTIONS,
    /// Last-level cache references.
    LlcReferences = PMU_EVENT_LLC_REFERENCES,
    /// Last-level cache misses.
    LlcMisses = PMU_EVENT_LLC_MISSES,
    /// Branch instructions retired.
    BranchInstructions = PMU_EVENT_BRANCH_INSTRUCTIONS,
    /// Mispredicted branch instructions retired.
    BranchMisses = PMU_EVENT_BRANCH_MISSES,
    /// Data-TLB misses that walked the page tables.
    DtlbMisses = PMU_EVENT_DTLB_MISSES,
    /// Instruction-TLB misses that walked the page tables.
    ItlbMisses = PMU_EVENT_ITLB_MISSES,
}

impl PmuEvent
{
    /// Every event, in id order.
    pub const ALL: [PmuEvent; PMU_EVENT_COUNT as usize] = [
        PmuEvent::Cycles,
        PmuEvent::Instructions,
        PmuEvent::LlcReferences,
        PmuEvent::LlcMisses,
        PmuEvent::BranchInstructions,
        PmuEvent::BranchMisses,
        PmuEvent::DtlbMisses,
        PmuEvent::ItlbMisses,
    ];

    /// The event with id `id`, or `None` for an id no event has.
    #[must_use]
    pub fn from_id(id: u8) -> Option<PmuEvent>
    {
        Self::ALL.get(usize::from(id)).copied()
    }

    /// The event's id, as the syscalls carry it.
    #[must_use]
    pub const fn id(self) -> u8
    {
        self as u8
    }

    /// The event's bit in a supported-event mask.
    #[must_use]
    pub const fn bit(self) -> u16
    {
        1 << self.id()
    }
}

/// Which execution a configuration counts: user mode, the kernel, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuMode
{
    /// User mode only.
    User,
    /// The kernel only.
    Kernel,
    /// Both.
    All,
}

impl PmuMode
{
    /// The mode of the syscall's mode word, or `None` for a word that names
    /// no mode (no bit, or a bit past [`PMU_MODE_KERNEL`]).
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<PmuMode>
    {
        match raw
        {
            PMU_MODE_USER => Some(PmuMode::User),
            PMU_MODE_KERNEL => Some(PmuMode::Kernel),
            x if x == PMU_MODE_USER | PMU_MODE_KERNEL => Some(PmuMode::All),
            _ => None,
        }
    }

    /// The syscall's mode word for this mode.
    #[must_use]
    pub const fn raw(self) -> u64
    {
        match self
        {
            PmuMode::User => PMU_MODE_USER,
            PmuMode::Kernel => PMU_MODE_KERNEL,
            PmuMode::All => PMU_MODE_USER | PMU_MODE_KERNEL,
        }
    }

    /// Whether the mode counts user mode.
    #[must_use]
    pub const fn counts_user(self) -> bool
    {
        self.raw() & PMU_MODE_USER != 0
    }

    /// Whether the mode counts the kernel.
    #[must_use]
    pub const fn counts_kernel(self) -> bool
    {
        self.raw() & PMU_MODE_KERNEL != 0
    }
}

/// A CPU's performance counters as `SYS_PMU_INFO` describes them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info
{
    /// The counters a configuration may take: every counter but the one the
    /// kernel keeps. 0 for a CPU with no PMU.
    pub counters: u8,
    /// The width of each counter in bits; a read wraps at `2^width`.
    pub width: u8,
    /// The supported events, one bit per [`PmuEvent::bit`].
    pub events: u16,
}

impl Info
{
    /// The description of a CPU with no PMU.
    pub const NONE: Info = Info {
        counters: 0,
        width: 0,
        events: 0,
    };

    /// Whether the CPU has a PMU a configuration can use.
    #[must_use]
    pub const fn present(self) -> bool
    {
        self.counters != 0
    }

    /// Whether the CPU counts `event`.
    #[must_use]
    pub const fn supports(self, event: PmuEvent) -> bool
    {
        self.events & event.bit() != 0
    }

    /// The `SYS_PMU_INFO` result word.
    #[must_use]
    pub fn pack(self) -> u64
    {
        ((u64::from(self.counters) & PMU_INFO_COUNTERS_MASK) << PMU_INFO_COUNTERS_SHIFT)
            | ((u64::from(self.width) & PMU_INFO_WIDTH_MASK) << PMU_INFO_WIDTH_SHIFT)
            | ((u64::from(self.events) & PMU_INFO_EVENTS_MASK) << PMU_INFO_EVENTS_SHIFT)
    }

    /// The description a `SYS_PMU_INFO` result word carries.
    #[must_use]
    pub const fn unpack(word: u64) -> Info
    {
        Info {
            counters: ((word >> PMU_INFO_COUNTERS_SHIFT) & PMU_INFO_COUNTERS_MASK) as u8,
            width: ((word >> PMU_INFO_WIDTH_SHIFT) & PMU_INFO_WIDTH_MASK) as u8,
            events: ((word >> PMU_INFO_EVENTS_SHIFT) & PMU_INFO_EVENTS_MASK) as u16,
        }
    }
}

/// Why an event list is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventListError
{
    /// More than [`PMU_CONFIGURE_MAX`] events.
    TooMany,
    /// An id no event has.
    Unknown,
    /// An event named twice.
    Repeated,
}

/// The events of one configuration, in the order their handles are returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventList
{
    events: [PmuEvent; PMU_CONFIGURE_MAX],
    len: usize,
}

impl EventList
{
    /// The list of `events`, refused when it is longer than
    /// [`PMU_CONFIGURE_MAX`] or names an event twice.
    ///
    /// # Errors
    /// [`EventListError::TooMany`] or [`EventListError::Repeated`].
    pub fn new(events: &[PmuEvent]) -> Result<EventList, EventListError>
    {
        if events.len() > PMU_CONFIGURE_MAX
        {
            return Err(EventListError::TooMany);
        }
        let mut list = EventList {
            events: [PmuEvent::Cycles; PMU_CONFIGURE_MAX],
            len: events.len(),
        };
        let mut seen: u16 = 0;
        for (slot, &event) in list.events.iter_mut().zip(events)
        {
            if seen & event.bit() != 0
            {
                return Err(EventListError::Repeated);
            }
            seen |= event.bit();
            *slot = event;
        }
        Ok(list)
    }

    /// The list `SYS_PMU_CONFIGURE`'s event word and count carry: `n` ids,
    /// one per byte from the low byte up. The bytes past the `n`th are
    /// ignored.
    ///
    /// # Errors
    /// [`EventListError::TooMany`] for `n` past [`PMU_CONFIGURE_MAX`],
    /// [`EventListError::Unknown`] for an id no event has, and
    /// [`EventListError::Repeated`] for an event named twice.
    pub fn decode(word: u64, n: u64) -> Result<EventList, EventListError>
    {
        let n = usize::try_from(n).map_err(|_| EventListError::TooMany)?;
        if n > PMU_CONFIGURE_MAX
        {
            return Err(EventListError::TooMany);
        }
        let mut events = [PmuEvent::Cycles; PMU_CONFIGURE_MAX];
        for (i, slot) in events.iter_mut().enumerate().take(n)
        {
            *slot = PmuEvent::from_id(entry(word, i)).ok_or(EventListError::Unknown)?;
        }
        EventList::new(events.get(..n).ok_or(EventListError::TooMany)?)
    }

    /// The event word that carries this list.
    #[must_use]
    pub fn encode(&self) -> u64
    {
        let mut word = 0;
        for (i, event) in self.as_slice().iter().enumerate()
        {
            word |= u64::from(event.id()) << shift(i);
        }
        word
    }

    /// The events, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[PmuEvent]
    {
        self.events.get(..self.len).unwrap_or(&[])
    }

    /// The number of events.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the list is empty, as a release is.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The events as a mask, one bit per [`PmuEvent::bit`].
    #[must_use]
    pub fn mask(&self) -> u16
    {
        self.as_slice().iter().fold(0, |m, e| m | e.bit())
    }
}

/// Entry `i` of an event word or a handle word.
#[must_use]
pub const fn entry(word: u64, i: usize) -> u8
{
    ((word >> shift(i)) & PMU_ENTRY_MASK) as u8
}

/// The shift of entry `i`; `i` is below [`PMU_CONFIGURE_MAX`].
#[expect(
    clippy::cast_possible_truncation,
    reason = "i is below PMU_CONFIGURE_MAX, eight, so the product is below 64"
)]
const fn shift(i: usize) -> u32
{
    (i as u32).wrapping_mul(PMU_ENTRY_BITS)
}

/// The `SYS_PMU_CONFIGURE` result word for `handles`, one per byte in the
/// order of the configuration's events. `handles` is at most
/// [`PMU_CONFIGURE_MAX`] long.
#[must_use]
pub fn pack_handles(handles: &[u8]) -> u64
{
    handles
        .iter()
        .take(PMU_CONFIGURE_MAX)
        .enumerate()
        .fold(0, |word, (i, &h)| word | (u64::from(h) << shift(i)))
}

/// The count between two reads `start` and `end` of a counter `width` bits
/// wide, across at most one wrap; a `width` of 64 or more is the full word.
#[must_use]
pub const fn delta(start: u64, end: u64, width: u8) -> u64
{
    let mask = if width >= 64
    {
        u64::MAX
    }
    else
    {
        (1u64 << width).wrapping_sub(1)
    };
    end.wrapping_sub(start) & mask
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect guarded: an id and its mask bit drifting from the ABI constants,
    // so the kernel and a client disagree on which event a byte names.
    #[test]
    fn every_event_round_trips_through_its_id()
    {
        for (i, event) in PmuEvent::ALL.iter().enumerate()
        {
            assert_eq!(usize::from(event.id()), i);
            assert_eq!(PmuEvent::from_id(event.id()), Some(*event));
            assert_eq!(event.bit(), 1 << i);
        }
        assert_eq!(PmuEvent::from_id(PMU_EVENT_COUNT), None);
        assert_eq!(PmuEvent::from_id(u8::MAX), None);
    }

    // Defect guarded: a field packed past its mask into the next one, or read
    // back from the wrong shift.
    #[test]
    fn info_packs_each_field_into_its_own_bits()
    {
        let info = Info {
            counters: 7,
            width: 48,
            events: 0b1010_0011,
        };
        let word = info.pack();
        assert_eq!(word, 7 | (48 << 8) | (0b1010_0011 << 16));
        assert_eq!(Info::unpack(word), info);
        assert!(info.supports(PmuEvent::Cycles));
        assert!(!info.supports(PmuEvent::LlcReferences));
        assert!(!Info::NONE.present());
        assert_eq!(Info::NONE.pack(), 0);
    }

    // Defect guarded: a mode word with no bit, or with a bit no mode has,
    // read as a mode.
    #[test]
    fn only_the_three_mode_words_name_a_mode()
    {
        for mode in [PmuMode::User, PmuMode::Kernel, PmuMode::All]
        {
            assert_eq!(PmuMode::from_raw(mode.raw()), Some(mode));
        }
        assert_eq!(PmuMode::from_raw(0), None);
        assert_eq!(PmuMode::from_raw(4), None);
        assert_eq!(PmuMode::from_raw(7), None);
        assert!(PmuMode::All.counts_user() && PmuMode::All.counts_kernel());
        assert!(PmuMode::User.counts_user() && !PmuMode::User.counts_kernel());
        assert!(!PmuMode::Kernel.counts_user() && PmuMode::Kernel.counts_kernel());
    }

    // Defect guarded: an event list that accepts a repeated or unknown id,
    // more events than the word holds, or reads the bytes past its count.
    #[test]
    fn an_event_word_decodes_to_its_list_or_is_refused_by_name()
    {
        let list = EventList::new(&[PmuEvent::Instructions, PmuEvent::Cycles]).unwrap();
        let word = list.encode();
        assert_eq!(word, 0x0001);
        assert_eq!(EventList::decode(word, 2), Ok(list));
        // Bytes past n are ignored.
        assert_eq!(EventList::decode(word | (0xFF << 16), 2), Ok(list));
        assert_eq!(EventList::decode(0, 0).map(|l| l.len()), Ok(0));
        assert_eq!(EventList::decode(0x0000, 2), Err(EventListError::Repeated));
        assert_eq!(EventList::decode(0x08, 1), Err(EventListError::Unknown));
        assert_eq!(EventList::decode(0, 9), Err(EventListError::TooMany));
        assert_eq!(EventList::decode(0, u64::MAX), Err(EventListError::TooMany));
        let all = EventList::new(&PmuEvent::ALL).unwrap();
        assert_eq!(all.encode(), 0x0706_0504_0302_0100);
        assert_eq!(EventList::decode(all.encode(), 8), Ok(all));
        assert_eq!(all.mask(), 0xFF);
    }

    // Defect guarded: a handle written to another event's byte.
    #[test]
    fn handles_pack_in_event_order()
    {
        let word = pack_handles(&[3, 0x40, 9]);
        assert_eq!(word, 0x09_40_03);
        assert_eq!(entry(word, 0), 3);
        assert_eq!(entry(word, 1), 0x40);
        assert_eq!(entry(word, 2), 9);
        assert_eq!(entry(word, 3), 0);
    }

    // Defect guarded: a delta across a wrap read as a huge count, or a
    // 64-bit counter's mask overflowing the shift.
    #[test]
    fn delta_masks_to_the_counter_width()
    {
        assert_eq!(delta(10, 25, 48), 15);
        assert_eq!(delta((1 << 48) - 5, 3, 48), 8);
        assert_eq!(delta(u64::MAX - 1, 2, 64), 4);
        assert_eq!(delta(5, 5, 0), 0);
    }
}
