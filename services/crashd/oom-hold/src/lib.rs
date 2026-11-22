// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/oom-hold/src/lib.rs

//! What crashd decides about a fault memmgr declined for want of memory:
//! whether it holds it, until when, and which held fault ends how.
//!
//! crashd holds such a fault (memmgr's decline codes 6, 7, 8 and 11,
//! [`holdable`]) in one of [`SLOTS`] slots for at most its stall
//! (`CRASHD_OOM_STALL_MS`, [`parse_stall`]), resumes it when the memory it
//! waits for is there ([`Waits`]: for a commit overrun, code 11, memmgr's draw
//! room opening; for code 7, the level falling below `CRITICAL` or the draw
//! room opening; for the others, memmgr's pressure level falling below
//! `CRITICAL`), and reports and declines it when the stall passes first. A
//! fault it resumed that faults again at the same page is a repeat: held again
//! only until its first hold's deadline while its memory is short. With its
//! memory there, a repeat of a fault that waits on the level is declined at
//! once, so no fault loops on memory that came back and memmgr still cannot
//! give it; one of a commit overrun is resumed again, remembered until that
//! deadline, since one opening of the draw room backs one committed draw and
//! another draw may have taken it first. The holds of one fault total at most
//! the stall (`services/crashd/docs/operation.md` § Hold). A
//! redirected fault reaches its slot's endpoint only when its thread next
//! runs, so a hold ends when its memory is there only once its fault has
//! arrived ([`Holds::arrived`]). A
//! held fault the kernel withdraws from its slot after it arrived (a stop, a
//! destroy, a rebind) ends with nothing to answer and is not remembered; one
//! that has not arrived when its stall passes is undelivered, and its slot's
//! endpoint is replaced before the slot is used again. The state takes the time as an argument
//! and holds no capability, so it is host-tested; crashd keeps each held
//! fault's message and endpoint beside its slot.

#![cfg_attr(not(test), no_std)]

/// Faults crashd holds at once, and resumed faults it remembers for the
/// repeat rule. Each slot costs crashd one endpoint, made at start.
pub const SLOTS: usize = 16;

/// The longest stall crashd takes, in milliseconds: ten minutes. A longer
/// `CRASHD_OOM_STALL_MS` is clamped to it.
pub const STALL_MAX_MS: u64 = 600_000;

/// memmgr's decline codes for a fault it could not back for want of memory:
/// 6, the metadata arena cannot grow for the run's slots; 7, no free page can
/// back the faulting page; 8, the run cannot be recorded in the region's chunk
/// table; 11, a commit overrun, a committed page with no free frame for it
/// (`services/memmgr/docs/ipc-interface.md`, the fault arm's table). Code 10,
/// a budget node's max, is the process's own limit and is never held.
const HOLDABLE_CODES: [u64; 4] = [6, 7, 8, 11];

/// Whether a pager's decline reason word names a decline for want of memory
/// ([`HOLDABLE_CODES`]): the code is its low 32 bits.
#[must_use]
pub fn holdable(reason: u64) -> bool
{
    HOLDABLE_CODES.contains(&(reason & 0xffff_ffff))
}

/// The stall `CRASHD_OOM_STALL_MS` sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stall
{
    /// Milliseconds a fault is held at most; 0 holds none.
    pub ms: u64,
    /// Whether the value asked more than [`STALL_MAX_MS`] and was clamped to
    /// it.
    pub clamped: bool,
}

/// A `CRASHD_OOM_STALL_MS` value that is not a decimal number of
/// milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotMilliseconds;

/// The stall the environment value `value` sets: no entry holds no fault, as
/// 0 does, and a value past [`STALL_MAX_MS`] is clamped to it.
///
/// # Errors
/// [`NotMilliseconds`] when the value is not decimal digits alone, an empty
/// one included.
pub fn parse_stall(value: Option<&str>) -> Result<Stall, NotMilliseconds>
{
    let Some(text) = value
    else
    {
        return Ok(Stall {
            ms: 0,
            clamped: false,
        });
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(NotMilliseconds);
    }
    // Digits alone: the parse fails only past u64::MAX, which is past the max.
    let ms = text.parse::<u64>().unwrap_or(u64::MAX);
    Ok(Stall {
        ms: ms.min(STALL_MAX_MS),
        clamped: ms > STALL_MAX_MS,
    })
}

/// What a held fault waits for, by memmgr's decline code ([`waits_on`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waits
{
    /// memmgr's pressure level below `CRITICAL`: a fault memmgr declined
    /// with code 6 or 8, which a page outside the system reserve backs, and
    /// the repeat of a code-7 fault ([`Waits::LevelOrDrawRoom`]).
    Level,
    /// Either of the level below `CRITICAL` and the draw room open: a fault
    /// memmgr declined with code 7. That code is a demand page no free page
    /// outside `promised` and the growth floor can back, which waits on the
    /// level, or a restore of an evicted chunk the free frames do not cover
    /// while swap slots are registered, which the evictions that raise the
    /// free frames admit while the level, read from the uncommitted free
    /// pages, stays `CRITICAL` (`services/memmgr/docs/memory-pool.md`
    /// § Eviction, Restore headroom); an open draw room has room for a
    /// chunk's restore. The decline word does not tell the two apart, so a
    /// fault resumed on one of them that repeats waits on the level alone
    /// ([`Holds::admit`]): a demand page resumed on the draw room is declined
    /// again at most once per hold.
    LevelOrDrawRoom,
    /// memmgr's draw room open, at a demand chunk's bytes or more
    /// (`QUERY_POOL_STATUS` `data[16]`, room for any one committed draw): a commit
    /// overrun, code 11, a committed page the free frames outside the system
    /// reserve back, which write-out to swap can free while the level stays
    /// `CRITICAL` (`services/memmgr/docs/memory-pool.md` § Commit,
    /// Overcommit).
    DrawRoom,
}

/// What the fault of decline reason word `reason` waits for: its code is the
/// word's low 32 bits.
#[must_use]
pub const fn waits_on(reason: u64) -> Waits
{
    match reason & 0xffff_ffff
    {
        11 => Waits::DrawRoom,
        7 => Waits::LevelOrDrawRoom,
        _ => Waits::Level,
    }
}

/// Whether the memory a fault waits for is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Room
{
    /// It is not: the level is `CRITICAL` (at or below memmgr's growth floor,
    /// the system reserve and, while pages are swapped, the restore headroom),
    /// or the draw room is below a demand chunk.
    Short,
    /// It is: the level is `LOW` or `NORMAL`, or the draw room is open.
    Open,
}

/// memmgr's memory as crashd last read it: the room for each kind of fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rooms
{
    /// For a fault that waits on the level.
    pub level: Room,
    /// For a fault that waits on the draw room.
    pub draw: Room,
}

impl Rooms
{
    /// The room for a fault that waits for `waits`.
    #[must_use]
    pub const fn of(self, waits: Waits) -> Room
    {
        match (waits, self.level, self.draw)
        {
            (Waits::Level, level, _) => level,
            (Waits::DrawRoom, _, draw) => draw,
            (Waits::LevelOrDrawRoom, Room::Open, _) | (Waits::LevelOrDrawRoom, _, Room::Open) =>
            {
                Room::Open
            }
            (Waits::LevelOrDrawRoom, Room::Short, Room::Short) => Room::Short,
        }
    }
}

/// The faulting thread and page a fault names: the fault message's badge,
/// which names the thread, and the faulting address's page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key
{
    pub badge: u64,
    pub page: u64,
}

/// What crashd does with a holdable fault ([`Holds::admit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit
{
    /// Hold it in `slot` until `deadline`.
    Hold
    {
        slot: usize, deadline: u64
    },
    /// Resume it at once: its memory came back after memmgr declined it.
    Resume,
    /// Report and decline it now.
    Decline(Refusal),
}

/// Why a holdable fault is declined at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// Every slot holds a fault.
    SlotsFull,
    /// It repeats a fault crashd resumed that waits on the level, and the
    /// level is not `CRITICAL`.
    Repeat,
    /// The stall is 0: no fault is held.
    NoStall,
}

/// A fault held in a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held
{
    pub key: Key,
    /// What it waits for.
    pub waits: Waits,
    /// When the hold began.
    pub since: u64,
    /// When the stall passes: the hold's own, or for a repeat its first
    /// hold's.
    pub deadline: u64,
    /// Whether the fault has been seen queued on the slot's endpoint.
    pub arrived: bool,
}

/// Why crashd ends a hold ([`Holds::end`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why
{
    /// The memory it waits for is there ([`Rooms::of`]).
    RoomOpened,
    /// The hold's deadline passed ([`Holds::due`]).
    Due,
}

/// What crashd's receive on a held fault's slot endpoint found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found
{
    /// The held fault, whose reply crashd now holds.
    Fault,
    /// Nothing: the fault has not arrived yet, or was withdrawn after it
    /// arrived.
    Nothing,
}

/// How a hold ended ([`Holds::end`]), with the fault it held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended
{
    /// Resume the fault, which crashd remembers for the repeat rule.
    Resume(Held),
    /// Report and decline the fault: its stall passed.
    Decline(Held),
    /// The fault arrived and was no longer queued on the slot's endpoint;
    /// nothing to answer.
    Withdrawn(Held),
    /// The stall passed before the fault arrived: it may still reach the
    /// slot's endpoint, which crashd replaces before the slot holds another
    /// fault.
    Undelivered(Held),
}

/// A fault crashd resumed, remembered until its hold's deadline.
#[derive(Clone, Copy, Debug)]
struct Resumed
{
    key: Key,
    deadline: u64,
}

/// The held faults and the resumed ones the repeat rule reads. Times are in
/// the caller's milliseconds.
#[derive(Debug)]
pub struct Holds
{
    stall_ms: u64,
    held: [Option<Held>; SLOTS],
    /// Slots crashd took out of use, their endpoints gone ([`Holds::retire`]).
    retired: [bool; SLOTS],
    resumed: [Option<Resumed>; SLOTS],
}

impl Holds
{
    /// No fault held; each holdable fault is held for at most `stall_ms`.
    #[must_use]
    pub const fn new(stall_ms: u64) -> Self
    {
        Self {
            stall_ms,
            held: [None; SLOTS],
            retired: [false; SLOTS],
            resumed: [None; SLOTS],
        }
    }

    /// Decide a holdable fault of `key`, which waits for `waits`, that arrives
    /// at `now` with memmgr's memory at `rooms`. A first fault is held until
    /// the stall passes while its memory is short and resumed at once when it
    /// is there; a repeat of a resumed one is held until its first hold's
    /// deadline while its memory is short, and, when it is there, declined
    /// for a fault that waits on the level and resumed again, remembered until
    /// that deadline, for a commit overrun, which another draw may have
    /// beaten to the draw room. A repeat of a fault that waits on
    /// [`Waits::LevelOrDrawRoom`] waits on the level alone, so a demand page
    /// the draw room does not back is resumed into memmgr's decline at most
    /// once. A
    /// hold takes the slot [`Admit::Hold`] names, which [`Self::end`] frees;
    /// an [`Admit::Resume`] is remembered for the repeat rule.
    pub fn admit(&mut self, now: u64, key: Key, waits: Waits, rooms: Rooms) -> Admit
    {
        if self.stall_ms == 0
        {
            return Admit::Decline(Refusal::NoStall);
        }
        self.forget_expired(now);
        let repeat = self.take_resumed(key);
        let waits = match (repeat, waits)
        {
            (Some(_), Waits::LevelOrDrawRoom) => Waits::Level,
            _ => waits,
        };
        match (repeat, rooms.of(waits))
        {
            (Some(deadline), Room::Open) if waits == Waits::DrawRoom =>
            {
                self.remember(key, deadline);
                Admit::Resume
            }
            (Some(_), Room::Open) => Admit::Decline(Refusal::Repeat),
            (Some(deadline), Room::Short) => self.hold(key, waits, now, deadline),
            (None, Room::Open) =>
            {
                self.remember(key, now.saturating_add(self.stall_ms));
                Admit::Resume
            }
            (None, Room::Short) => self.hold(key, waits, now, now.saturating_add(self.stall_ms)),
        }
    }

    /// Hold `key`, which waits for `waits`, in a free slot until `deadline`.
    fn hold(&mut self, key: Key, waits: Waits, now: u64, deadline: u64) -> Admit
    {
        let Some((slot, free)) = self
            .held
            .iter_mut()
            .zip(self.retired)
            .enumerate()
            .find(|(_, (held, retired))| held.is_none() && !retired)
            .map(|(slot, (free, _))| (slot, free))
        else
        {
            return Admit::Decline(Refusal::SlotsFull);
        };
        *free = Some(Held {
            key,
            waits,
            since: now,
            deadline,
            arrived: false,
        });
        Admit::Hold { slot, deadline }
    }

    /// Record that the fault held in `slot` was seen queued on the slot's
    /// endpoint.
    pub fn arrived(&mut self, slot: usize)
    {
        if let Some(Some(held)) = self.held.get_mut(slot)
        {
            held.arrived = true;
        }
    }

    /// Free `slot` with nothing to end: the redirect that would have queued
    /// its fault failed.
    pub fn cancel(&mut self, slot: usize) -> Option<Held>
    {
        self.held.get_mut(slot).and_then(Option::take)
    }

    /// Take `slot` out of use: crashd could not replace its endpoint after an
    /// undelivered fault.
    pub fn retire(&mut self, slot: usize)
    {
        if let Some(retired) = self.retired.get_mut(slot)
        {
            *retired = true;
        }
    }

    /// End the hold in `slot` because `why`, with what crashd's receive
    /// `found` on the slot's endpoint, and free the slot; `None` when it held
    /// no fault, or when its memory came back before the fault arrived, which
    /// keeps the hold until the fault arrives or its deadline passes.
    ///
    /// A fault found is resumed when its memory came back, and remembered for the
    /// repeat rule until its deadline, or declined when its deadline passed.
    /// Nothing found after the fault arrived means it was withdrawn: its
    /// thread was stopped (a debugger's attach), destroyed with its process,
    /// or its exception class rebound, and the kernel ended or redelivered
    /// it, so crashd neither replies to it nor remembers it. Nothing found
    /// at the deadline before the fault arrived leaves it undelivered.
    pub fn end(&mut self, slot: usize, why: Why, found: Found) -> Option<Ended>
    {
        let cell = self.held.get_mut(slot)?;
        let held = (*cell)?;
        if let (Found::Nothing, false, Why::RoomOpened) = (found, held.arrived, why)
        {
            return None;
        }
        *cell = None;
        Some(match (found, why)
        {
            (Found::Nothing, _) if held.arrived => Ended::Withdrawn(held),
            (Found::Nothing, _) => Ended::Undelivered(held),
            (Found::Fault, Why::RoomOpened) =>
            {
                self.remember(held.key, held.deadline);
                Ended::Resume(held)
            }
            (Found::Fault, Why::Due) => Ended::Decline(held),
        })
    }

    /// The slots that hold a fault.
    pub fn held_slots(&self) -> impl Iterator<Item = usize> + '_
    {
        self.held
            .iter()
            .enumerate()
            .filter_map(|(slot, held)| held.map(|_| slot))
    }

    /// The slots that hold a fault whose memory is there at `rooms`.
    pub fn opened(&self, rooms: Rooms) -> impl Iterator<Item = usize> + '_
    {
        self.held
            .iter()
            .enumerate()
            .filter_map(move |(slot, held)| {
                held.filter(|h| rooms.of(h.waits) == Room::Open)
                    .map(|_| slot)
            })
    }

    /// A slot whose hold's deadline has passed at `now`, the earliest first;
    /// `None` when no hold is due.
    #[must_use]
    pub fn due(&self, now: u64) -> Option<usize>
    {
        self.held
            .iter()
            .enumerate()
            .filter_map(|(slot, held)| held.map(|h| (slot, h.deadline)))
            .filter(|&(_, deadline)| deadline <= now)
            .min_by_key(|&(_, deadline)| deadline)
            .map(|(slot, _)| slot)
    }

    /// The earliest deadline of a held fault; `None` while none is held.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64>
    {
        self.held.iter().flatten().map(|h| h.deadline).min()
    }

    /// Remember a resumed fault of `key` until `deadline`, in place of an
    /// earlier entry of the same key, else in a free entry, else in place of
    /// the entry that expires first.
    fn remember(&mut self, key: Key, deadline: u64)
    {
        let same = self
            .resumed
            .iter()
            .position(|r| r.is_some_and(|r| r.key == key));
        let free = self.resumed.iter().position(Option::is_none);
        let soonest = self
            .resumed
            .iter()
            .enumerate()
            .min_by_key(|(_, r)| r.map_or(0, |r| r.deadline))
            .map(|(at, _)| at);
        if let Some(cell) = same
            .or(free)
            .or(soonest)
            .and_then(|at| self.resumed.get_mut(at))
        {
            *cell = Some(Resumed { key, deadline });
        }
    }

    /// The deadline of a remembered resume of `key`, which this forgets.
    fn take_resumed(&mut self, key: Key) -> Option<u64>
    {
        self.resumed
            .iter_mut()
            .find(|r| r.is_some_and(|r| r.key == key))?
            .take()
            .map(|r| r.deadline)
    }

    /// Forget each remembered resume whose deadline has passed at `now`: a
    /// fault after it is a new one.
    fn forget_expired(&mut self, now: u64)
    {
        for cell in &mut self.resumed
        {
            if cell.is_some_and(|r| r.deadline <= now)
            {
                *cell = None;
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const STALL: u64 = 5000;

    /// Memory short for every fault.
    const SHORT: Rooms = Rooms {
        level: Room::Short,
        draw: Room::Short,
    };

    /// Memory there for every fault.
    const OPEN: Rooms = Rooms {
        level: Room::Open,
        draw: Room::Open,
    };

    fn key(badge: u64) -> Key
    {
        Key {
            badge,
            page: 0x4000_0000,
        }
    }

    #[test]
    fn only_declines_for_want_of_memory_are_holdable()
    {
        // A commit overrun (11) is held as a page with no frame (7) is.
        for code in [6, 7, 8, 11]
        {
            assert!(holdable(code));
        }
        assert!(holdable((1 << 32) + 11));
        // A budget max (10), a refused access (4), no region (3), a failed
        // map (9) with its error magnitude in the high half, a chunk on disk
        // (12).
        for reason in [10, 4, 3, 9 | (5 << 32), 12, 0]
        {
            assert!(!holdable(reason));
        }
        // The code is the low half alone.
        assert!(holdable(7 | (1 << 32)));
    }

    #[test]
    fn the_stall_is_parsed_from_decimal_milliseconds_and_clamped()
    {
        let off = Stall {
            ms: 0,
            clamped: false,
        };
        assert_eq!(parse_stall(None), Ok(off));
        assert_eq!(parse_stall(Some("0")), Ok(off));
        assert_eq!(
            parse_stall(Some("10000")),
            Ok(Stall {
                ms: 10000,
                clamped: false
            })
        );
        let max = Stall {
            ms: STALL_MAX_MS,
            clamped: false,
        };
        assert_eq!(parse_stall(Some("600000")), Ok(max));
        let clamped = Stall {
            ms: STALL_MAX_MS,
            clamped: true,
        };
        assert_eq!(parse_stall(Some("600001")), Ok(clamped));
        assert_eq!(parse_stall(Some("99999999999999999999999")), Ok(clamped));
        for bad in ["", "-1", "+5", "5s", " 5", "0x10"]
        {
            assert_eq!(parse_stall(Some(bad)), Err(NotMilliseconds));
        }
    }

    #[test]
    fn a_zero_stall_holds_nothing()
    {
        let mut holds = Holds::new(0);
        assert_eq!(
            holds.admit(0, key(1), Waits::Level, SHORT),
            Admit::Decline(Refusal::NoStall)
        );
        assert_eq!(holds.next_deadline(), None);
    }

    #[test]
    fn a_fault_at_critical_is_held_until_the_stall_passes()
    {
        let mut holds = Holds::new(STALL);
        assert_eq!(
            holds.admit(100, key(1), Waits::Level, SHORT),
            Admit::Hold {
                slot: 0,
                deadline: 100 + STALL
            }
        );
        assert_eq!(holds.next_deadline(), Some(100 + STALL));
        assert_eq!(holds.due(100 + STALL - 1), None);
        assert_eq!(holds.due(100 + STALL), Some(0));
        let Some(Ended::Decline(held)) = holds.end(0, Why::Due, Found::Fault)
        else
        {
            panic!("not declined");
        };
        assert_eq!((held.key, held.since), (key(1), 100));
        assert_eq!(holds.end(0, Why::Due, Found::Fault), None);
        assert_eq!(holds.next_deadline(), None);
        // A fault declined at its deadline is not remembered: its thread died.
        assert_eq!(
            holds.admit(200 + STALL, key(1), Waits::Level, OPEN),
            Admit::Resume
        );
    }

    #[test]
    fn the_earliest_deadline_is_due_first()
    {
        let mut holds = Holds::new(STALL);
        let _ = holds.admit(10, key(1), Waits::Level, SHORT);
        let _ = holds.admit(5, key(2), Waits::Level, SHORT);
        let _ = holds.admit(20, key(3), Waits::Level, SHORT);
        assert_eq!(holds.next_deadline(), Some(5 + STALL));
        assert_eq!(holds.due(30 + STALL), Some(1));
        let _ = holds.end(1, Why::Due, Found::Fault);
        assert_eq!(holds.due(30 + STALL), Some(0));
        assert_eq!(holds.held_slots().collect::<Vec<_>>(), [0, 2]);
    }

    #[test]
    fn a_fault_past_the_last_slot_is_declined_and_a_freed_slot_is_reused()
    {
        let mut holds = Holds::new(STALL);
        for badge in 0..SLOTS as u64
        {
            assert!(matches!(
                holds.admit(0, key(badge), Waits::Level, SHORT),
                Admit::Hold { .. }
            ));
        }
        assert_eq!(
            holds.admit(0, key(99), Waits::Level, SHORT),
            Admit::Decline(Refusal::SlotsFull)
        );
        let _ = holds.end(3, Why::Due, Found::Fault);
        assert_eq!(
            holds.admit(1, key(99), Waits::Level, SHORT),
            Admit::Hold {
                slot: 3,
                deadline: 1 + STALL
            }
        );
    }

    #[test]
    fn a_first_fault_below_critical_is_resumed_and_its_repeat_declined()
    {
        // The level fell between memmgr's decline and crashd's receive.
        let mut holds = Holds::new(STALL);
        assert_eq!(holds.admit(0, key(1), Waits::Level, OPEN), Admit::Resume);
        assert_eq!(
            holds.admit(1, key(1), Waits::Level, OPEN),
            Admit::Decline(Refusal::Repeat)
        );
        // Another thread, or another page of the same one, is a first fault.
        assert_eq!(holds.admit(2, key(2), Waits::Level, OPEN), Admit::Resume);
        let other_page = Key {
            badge: 1,
            page: 0x5000_0000,
        };
        assert_eq!(
            holds.admit(2, other_page, Waits::Level, OPEN),
            Admit::Resume
        );
    }

    #[test]
    fn a_repeat_at_critical_is_held_only_until_its_first_deadline()
    {
        let mut holds = Holds::new(STALL);
        let Admit::Hold { slot, deadline } = holds.admit(0, key(1), Waits::Level, SHORT)
        else
        {
            panic!("not held");
        };
        // The level fell: crashd resumes it, and memmgr declines it again.
        assert!(matches!(
            holds.end(slot, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
        assert_eq!(
            holds.admit(1000, key(1), Waits::Level, SHORT),
            Admit::Hold { slot, deadline }
        );
        // Resumed again, its next repeat below CRITICAL is declined.
        assert!(matches!(
            holds.end(slot, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
        assert_eq!(
            holds.admit(2000, key(1), Waits::Level, OPEN),
            Admit::Decline(Refusal::Repeat)
        );
    }

    #[test]
    fn a_fault_after_its_first_holds_deadline_is_a_new_one()
    {
        let mut holds = Holds::new(STALL);
        let _ = holds.admit(0, key(1), Waits::Level, SHORT);
        assert!(matches!(
            holds.end(0, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
        assert_eq!(
            holds.admit(STALL, key(1), Waits::Level, SHORT),
            Admit::Hold {
                slot: 0,
                deadline: 2 * STALL
            }
        );
    }

    #[test]
    fn a_full_memory_of_resumes_forgets_the_one_that_expires_first()
    {
        let mut holds = Holds::new(STALL);
        for badge in 0..SLOTS as u64
        {
            assert_eq!(
                holds.admit(badge, key(badge), Waits::Level, OPEN),
                Admit::Resume
            );
        }
        // Badge 0's entry expires first and gives way to badge 99's.
        assert_eq!(holds.admit(100, key(99), Waits::Level, OPEN), Admit::Resume);
        assert_eq!(holds.admit(101, key(0), Waits::Level, OPEN), Admit::Resume);
        assert_eq!(
            holds.admit(102, key(99), Waits::Level, OPEN),
            Admit::Decline(Refusal::Repeat)
        );
        assert_eq!(
            holds.admit(103, key(5), Waits::Level, OPEN),
            Admit::Decline(Refusal::Repeat)
        );
    }
    #[test]
    fn a_withdrawn_fault_frees_its_slot_and_is_not_remembered()
    {
        // A debugger's attach stops the held thread, or its process is
        // destroyed: the slot's endpoint holds nothing when crashd ends the
        // hold, whichever way it ends.
        let mut holds = Holds::new(STALL);
        for why in [Why::RoomOpened, Why::Due]
        {
            let Admit::Hold { slot, .. } = holds.admit(0, key(1), Waits::Level, SHORT)
            else
            {
                panic!("not held");
            };
            holds.arrived(slot);
            let Some(Ended::Withdrawn(held)) = holds.end(slot, why, Found::Nothing)
            else
            {
                panic!("not withdrawn");
            };
            assert_eq!(held.key, key(1));
            assert_eq!(holds.next_deadline(), None);
            assert_eq!(holds.held_slots().count(), 0);
        }
        // The thread, started again, faults afresh: a first fault, held for
        // a full stall at CRITICAL and resumed at once below it.
        assert_eq!(
            holds.admit(100, key(1), Waits::Level, SHORT),
            Admit::Hold {
                slot: 0,
                deadline: 100 + STALL
            }
        );
        holds.arrived(0);
        let _ = holds.end(0, Why::Due, Found::Nothing);
        assert_eq!(holds.admit(200, key(1), Waits::Level, OPEN), Admit::Resume);
    }

    #[test]
    fn a_fall_of_the_level_before_the_fault_arrives_keeps_the_hold()
    {
        // crashd's redirect reply returned, but the faulting thread has not
        // run since: its fault is not queued on the slot's endpoint yet.
        let mut holds = Holds::new(STALL);
        let Admit::Hold { slot, deadline } = holds.admit(0, key(1), Waits::Level, SHORT)
        else
        {
            panic!("not held");
        };
        assert_eq!(holds.end(slot, Why::RoomOpened, Found::Nothing), None);
        assert_eq!(holds.held_slots().collect::<Vec<_>>(), [slot]);
        assert_eq!(holds.next_deadline(), Some(deadline));
        // The fault arrives and is resumed.
        holds.arrived(slot);
        assert!(matches!(
            holds.end(slot, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
        // A receive that finds the fault before its arrival was seen resumes
        // it too.
        let Admit::Hold { slot, .. } = holds.admit(10, key(2), Waits::Level, SHORT)
        else
        {
            panic!("not held");
        };
        assert!(matches!(
            holds.end(slot, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
    }

    #[test]
    fn a_fault_not_arrived_at_its_deadline_is_undelivered_and_not_remembered()
    {
        let mut holds = Holds::new(STALL);
        let Admit::Hold { slot, .. } = holds.admit(0, key(1), Waits::Level, SHORT)
        else
        {
            panic!("not held");
        };
        assert_eq!(holds.due(STALL), Some(slot));
        let Some(Ended::Undelivered(held)) = holds.end(slot, Why::Due, Found::Nothing)
        else
        {
            panic!("not undelivered");
        };
        assert_eq!(held.key, key(1));
        assert_eq!(holds.next_deadline(), None);
        // The slot is free again, its endpoint replaced by crashd; the same
        // thread faulting afresh is a first fault.
        assert_eq!(
            holds.admit(STALL + 1, key(1), Waits::Level, SHORT),
            Admit::Hold {
                slot,
                deadline: 2 * STALL + 1
            }
        );
    }

    #[test]
    fn a_retired_slot_holds_no_fault_and_a_cancelled_one_is_reused()
    {
        let mut holds = Holds::new(STALL);
        holds.retire(0);
        let Admit::Hold { slot, .. } = holds.admit(0, key(1), Waits::Level, SHORT)
        else
        {
            panic!("not held");
        };
        assert_eq!(slot, 1);
        assert_eq!(holds.cancel(slot).map(|h| h.key), Some(key(1)));
        assert_eq!(holds.held_slots().count(), 0);
        assert_eq!(
            holds.admit(1, key(2), Waits::Level, SHORT),
            Admit::Hold {
                slot: 1,
                deadline: 1 + STALL
            }
        );
        for badge in 3..=(SLOTS as u64)
        {
            assert!(matches!(
                holds.admit(2, key(badge), Waits::Level, SHORT),
                Admit::Hold { .. }
            ));
        }
        assert_eq!(
            holds.admit(3, key(99), Waits::Level, SHORT),
            Admit::Decline(Refusal::SlotsFull)
        );
    }

    #[test]
    fn a_commit_overrun_waits_on_the_draw_room_and_the_others_on_the_level()
    {
        assert_eq!(waits_on(11), Waits::DrawRoom);
        assert_eq!(waits_on((1 << 32) + 11), Waits::DrawRoom);
        assert_eq!(waits_on(7), Waits::LevelOrDrawRoom);
        for code in [6, 8]
        {
            assert_eq!(waits_on(code), Waits::Level);
        }
        // The level below CRITICAL, the draw room 0: a commit overrun is held,
        // a fault of code 7 resumed at once.
        let level_only = Rooms {
            level: Room::Open,
            draw: Room::Short,
        };
        let mut holds = Holds::new(STALL);
        let Admit::Hold { slot: commit, .. } = holds.admit(0, key(1), waits_on(11), level_only)
        else
        {
            panic!("a commit overrun with no draw room was not held");
        };
        assert_eq!(
            holds.admit(0, key(2), waits_on(7), level_only),
            Admit::Resume
        );
        // Held at CRITICAL, a fault of code 8 waits on the level alone.
        let Admit::Hold { slot: level, .. } = holds.admit(1, key(3), waits_on(8), SHORT)
        else
        {
            panic!("a fault of code 8 at CRITICAL was not held");
        };
        holds.arrived(commit);
        holds.arrived(level);
        // The draw room rising while the level stays CRITICAL opens the
        // commit overrun's hold only.
        let draw_only = Rooms {
            level: Room::Short,
            draw: Room::Open,
        };
        assert_eq!(holds.opened(draw_only).collect::<Vec<_>>(), [commit]);
        assert_eq!(holds.opened(level_only).collect::<Vec<_>>(), [level]);
        assert_eq!(holds.opened(SHORT).count(), 0);
        assert!(matches!(
            holds.end(commit, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(Held {
                waits: Waits::DrawRoom,
                ..
            }))
        ));
        // Its repeat with the draw room open is resumed again, since another
        // draw may have taken the room it was resumed on, and is remembered
        // until the first hold's deadline: a repeat then with the room short
        // is held only until that deadline, and one after it is a new fault.
        assert_eq!(
            holds.admit(2, key(1), waits_on(11), draw_only),
            Admit::Resume
        );
        let Admit::Hold {
            slot: again,
            deadline,
        } = holds.admit(3, key(1), waits_on(11), SHORT)
        else
        {
            panic!("a commit overrun's repeat with no draw room was not held");
        };
        assert_eq!(deadline, STALL);
        holds.arrived(again);
        assert_eq!(holds.opened(OPEN).collect::<Vec<_>>(), [again, level]);
        assert!(matches!(
            holds.end(again, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(_))
        ));
        assert_eq!(
            holds.admit(STALL + 1, key(1), waits_on(11), draw_only),
            Admit::Resume
        );
        assert_eq!(
            holds.admit(STALL + 2, key(1), waits_on(11), SHORT),
            Admit::Hold {
                slot: again,
                deadline: STALL + 1 + STALL
            }
        );
    }
    // The defect caught: a fault of code 7 whose chunk's restore memmgr
    // declined for want of free frames, held on the level alone, which the
    // evictions that free those frames leave at CRITICAL, so it runs to its
    // stall and is killed after its frames came back. It waits on either
    // room; a repeat of one resumed waits on the level alone, so a demand
    // page the draw room does not back is resumed into memmgr's decline at
    // most once per hold.
    #[test]
    fn a_fault_of_code_7_waits_on_the_level_or_the_draw_room()
    {
        let draw_only = Rooms {
            level: Room::Short,
            draw: Room::Open,
        };
        let level_only = Rooms {
            level: Room::Open,
            draw: Room::Short,
        };
        assert_eq!(draw_only.of(Waits::LevelOrDrawRoom), Room::Open);
        assert_eq!(level_only.of(Waits::LevelOrDrawRoom), Room::Open);
        assert_eq!(SHORT.of(Waits::LevelOrDrawRoom), Room::Short);
        let mut holds = Holds::new(STALL);
        let Admit::Hold { slot, deadline } = holds.admit(0, key(1), waits_on(7), SHORT)
        else
        {
            panic!("a fault of code 7 with both rooms short was not held");
        };
        holds.arrived(slot);
        // The draw room opening while the level stays CRITICAL resumes it.
        assert_eq!(holds.opened(draw_only).collect::<Vec<_>>(), [slot]);
        assert!(matches!(
            holds.end(slot, Why::RoomOpened, Found::Fault),
            Some(Ended::Resume(Held {
                waits: Waits::LevelOrDrawRoom,
                ..
            }))
        ));
        // Its repeat, the draw room still open and the level CRITICAL, is a
        // demand page the draw room does not back: held on the level alone,
        // until the first hold's deadline.
        let Admit::Hold {
            slot: again,
            deadline: kept,
        } = holds.admit(10, key(1), waits_on(7), draw_only)
        else
        {
            panic!("a repeat of code 7 at CRITICAL was not held");
        };
        assert_eq!(kept, deadline);
        holds.arrived(again);
        assert_eq!(holds.opened(draw_only).count(), 0);
        assert_eq!(holds.opened(level_only).collect::<Vec<_>>(), [again]);
        // A first fault of code 7 with the draw room open is resumed at once.
        assert_eq!(
            holds.admit(20, key(2), waits_on(7), draw_only),
            Admit::Resume
        );
    }
}
