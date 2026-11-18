// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/sessiond/table/src/lib.rs

//! sessiond's bookkeeping, as pure host-tested logic
//! (services/sessiond/README.md).
//!
//! [`Slots`] is a fixed table whose entries are named by a key of their slot
//! and a generation, so a key goes stale once its entry is removed and never
//! names the entry that next takes the slot. sessiond keeps its sessions and
//! its interfaces in one each, sized at build time, so no table operation
//! allocates. [`Key`] tells the two kinds of candidate key sessiond lists
//! apart: a session's carries [`SESSION_KEY_BIT`], a verb bit no procmgr
//! process badge carries, and a job's is the job's process badge. [`Page`]
//! places the entries of a `LIST_CANDIDATES` walk on the page a cursor asks
//! for. [`session_name`] is the name a session is listed under. Nothing here
//! makes a syscall.

#![cfg_attr(not(test), no_std)]

/// The bit every session key carries. procmgr draws process badges with
/// every verb bit clear (`ipc::VERB_BIT_MASK`), so no job key, a process
/// badge, carries it.
pub const SESSION_KEY_BIT: u64 = 1u64 << 63;

/// The bits of a key's generation, above its slot: the 31 bits below
/// [`SESSION_KEY_BIT`].
const GENERATION_MASK: u32 = 0x7FFF_FFFF;

/// The shift of a key's generation.
const GENERATION_SHIFT: u32 = 32;

/// What a candidate key names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key
{
    /// A job: the process badge of a child of a session's leader.
    Job(u64),
    /// A session: a key of the session table.
    Session(u64),
}

impl Key
{
    /// Read a key `STOP_CANDIDATE` names.
    #[must_use]
    pub const fn of(key: u64) -> Self
    {
        if key & SESSION_KEY_BIT == 0
        {
            Self::Job(key)
        }
        else
        {
            Self::Session(key)
        }
    }
}

/// A fixed table of `N` entries, each named by a key of its slot and the
/// slot's generation, with [`SESSION_KEY_BIT`] set.
pub struct Slots<T, const N: usize>
{
    entries: [Option<T>; N],
    generations: [u32; N],
}

impl<T, const N: usize> Default for Slots<T, N>
{
    fn default() -> Self
    {
        Self {
            entries: core::array::from_fn(|_| None),
            generations: [0; N],
        }
    }
}

impl<T, const N: usize> Slots<T, N>
{
    /// Put `value` in the first free slot, under a generation that slot has
    /// not had since it was last emptied, and return its key; `None`, with
    /// `value` dropped, when every slot is taken.
    pub fn insert(&mut self, value: T) -> Option<u64>
    {
        let slot = self.entries.iter().position(Option::is_none)?;
        let generation = self.generations.get_mut(slot)?;
        *generation = generation.wrapping_add(1) & GENERATION_MASK;
        let key = compose(slot, *generation)?;
        *self.entries.get_mut(slot)? = Some(value);
        Some(key)
    }

    /// Whether a slot is free.
    #[must_use]
    pub fn has_room(&self) -> bool
    {
        self.entries.iter().any(Option::is_none)
    }

    /// The entry `key` names; `None` for a key of a removed entry, of
    /// another kind, or of no slot.
    #[must_use]
    pub fn get(&self, key: u64) -> Option<&T>
    {
        let slot = self.slot_of(key)?;
        self.entries.get(slot)?.as_ref()
    }

    /// The entry `key` names, mutably; `None` as for [`Self::get`].
    pub fn get_mut(&mut self, key: u64) -> Option<&mut T>
    {
        let slot = self.slot_of(key)?;
        self.entries.get_mut(slot)?.as_mut()
    }

    /// Take the entry `key` names out of the table; `None` as for
    /// [`Self::get`]. The key is stale from then on.
    pub fn remove(&mut self, key: u64) -> Option<T>
    {
        let slot = self.slot_of(key)?;
        self.entries.get_mut(slot)?.take()
    }

    /// The key of the entry in `slot`; `None` for an empty slot or one past
    /// the table.
    #[must_use]
    pub fn key_at(&self, slot: usize) -> Option<u64>
    {
        self.entries.get(slot)?.as_ref()?;
        compose(slot, *self.generations.get(slot)?)
    }

    /// Every entry with its key, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &T)>
    {
        self.entries
            .iter()
            .zip(self.generations.iter())
            .enumerate()
            .filter_map(|(slot, (entry, &generation))| {
                Some((compose(slot, generation)?, entry.as_ref()?))
            })
    }

    /// The key of the first entry, in slot order, for which `found` holds.
    #[must_use]
    pub fn find(&self, mut found: impl FnMut(&T) -> bool) -> Option<u64>
    {
        self.iter()
            .find_map(|(key, entry)| found(entry).then_some(key))
    }

    /// The slot `key` names, when it carries [`SESSION_KEY_BIT`], its slot
    /// lies in the table, and its generation is the slot's.
    fn slot_of(&self, key: u64) -> Option<usize>
    {
        if key & SESSION_KEY_BIT == 0
        {
            return None;
        }
        let slot = usize::try_from(key & u64::from(u32::MAX)).ok()?;
        let generation = u32::try_from(key >> GENERATION_SHIFT).ok()? & GENERATION_MASK;
        (*self.generations.get(slot)? == generation).then_some(slot)
    }
}

/// The slot of a key: the low 32 bits.
#[must_use]
pub fn slot_of_key(key: u64) -> usize
{
    usize::try_from(key & u64::from(u32::MAX)).unwrap_or(usize::MAX)
}

/// The key of `slot` at `generation`; `None` for a slot past 32 bits.
fn compose(slot: usize, generation: u32) -> Option<u64>
{
    let slot = u32::try_from(slot).ok()?;
    Some(
        SESSION_KEY_BIT
            | (u64::from(generation & GENERATION_MASK) << GENERATION_SHIFT)
            | u64::from(slot),
    )
}

/// Where one entry of a `LIST_CANDIDATES` walk goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place
{
    /// Before the cursor: on an earlier page.
    Skip,
    /// At this index of the page.
    Take(usize),
    /// After the page: the walk stops.
    Full,
}

/// One page of a `LIST_CANDIDATES` walk: the cursor is the ordinal of the
/// first entry the page holds, counted over the walk's entries in their
/// order, and the page holds at most `room` of them. The walk is made again
/// for every page, so an entry that appears or goes between two pages moves
/// the later entries by one place: a later page may then repeat an entry or
/// miss one, which oomd's next act lists again.
pub struct Page
{
    cursor: u64,
    skip: u64,
    room: usize,
    taken: usize,
}

impl Page
{
    /// The page that starts at `cursor` and holds at most `room` entries.
    #[must_use]
    pub const fn new(cursor: u64, room: usize) -> Self
    {
        Self {
            cursor,
            skip: cursor,
            room,
            taken: 0,
        }
    }

    /// Place the walk's next entry.
    pub fn place(&mut self) -> Place
    {
        if self.skip > 0
        {
            self.skip = self.skip.saturating_sub(1);
            return Place::Skip;
        }
        if self.taken >= self.room
        {
            return Place::Full;
        }
        let index = self.taken;
        self.taken = self.taken.saturating_add(1);
        Place::Take(index)
    }

    /// Whether the page holds `room` entries, so a further entry would not fit.
    #[must_use]
    pub const fn is_full(&self) -> bool
    {
        self.taken >= self.room
    }

    /// The entries the page holds.
    #[must_use]
    pub const fn count(&self) -> usize
    {
        self.taken
    }

    /// The cursor that resumes the walk after this page: past every entry it
    /// holds, so greater than its own whenever the page is not empty.
    #[must_use]
    pub fn next_cursor(&self) -> u64
    {
        self.cursor
            .saturating_add(u64::try_from(self.taken).unwrap_or(u64::MAX))
    }
}

/// The longest name [`session_name`] writes: `session ` and the ten digits of
/// a `u32`.
pub const SESSION_NAME_MAX: usize = 18;

/// Write the name the session in `slot` is listed under, `session <slot>`, to
/// the front of `buf` and return it.
pub fn session_name(slot: u32, buf: &mut [u8; SESSION_NAME_MAX]) -> &[u8]
{
    const PREFIX: &[u8] = b"session ";
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    let mut rest = slot;
    loop
    {
        start = start.saturating_sub(1);
        if let Some(digit) = digits.get_mut(start)
        {
            // The remainder of a division by 10 is below 10.
            *digit = b'0'.saturating_add(u8::try_from(rest % 10).unwrap_or(0));
        }
        rest /= 10;
        if rest == 0 || start == 0
        {
            break;
        }
    }
    let number = digits.get(start..).unwrap_or_default();
    let len = PREFIX.len().saturating_add(number.len());
    if let Some((head, tail)) = buf.get_mut(..len).map(|b| b.split_at_mut(PREFIX.len()))
    {
        head.copy_from_slice(PREFIX);
        tail.copy_from_slice(number);
    }
    buf.get(..len).unwrap_or_default()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_removed_entrys_key_is_stale_and_its_slot_takes_a_new_key()
    {
        let mut slots: Slots<u32, 2> = Slots::default();
        let first = slots.insert(7).unwrap();
        assert_eq!(slots.get(first), Some(&7));
        assert_eq!(slots.remove(first), Some(7));
        assert_eq!(slots.get(first), None);
        assert_eq!(slots.remove(first), None);
        let second = slots.insert(8).unwrap();
        assert_eq!(slot_of_key(first), slot_of_key(second));
        assert_ne!(first, second);
        assert_eq!(slots.get(first), None);
        assert_eq!(slots.get(second), Some(&8));
    }

    #[test]
    fn a_full_table_refuses_an_insert_until_a_slot_is_freed()
    {
        let mut slots: Slots<u32, 2> = Slots::default();
        let a = slots.insert(1).unwrap();
        let b = slots.insert(2).unwrap();
        assert!(!slots.has_room());
        assert_eq!(slots.insert(3), None);
        assert_eq!(slots.remove(a), Some(1));
        assert!(slots.has_room());
        let c = slots.insert(3).unwrap();
        assert_eq!(slot_of_key(c), slot_of_key(a));
        let listed: Vec<(u64, u32)> = slots.iter().map(|(k, &v)| (k, v)).collect();
        assert_eq!(listed, [(c, 3), (b, 2)]);
        assert_eq!(slots.key_at(0), Some(c));
        assert_eq!(slots.find(|&v| v == 2), Some(b));
    }

    #[test]
    fn keys_outside_the_table_name_no_entry()
    {
        let mut slots: Slots<u32, 2> = Slots::default();
        let key = slots.insert(1).unwrap();
        // A job key, a slot past the table, and every bit set.
        assert_eq!(slots.get(key & !SESSION_KEY_BIT), None);
        assert_eq!(slots.get(key | 5), None);
        assert_eq!(slots.get(u64::MAX), None);
        assert_eq!(slots.key_at(1), None);
        assert_eq!(slots.key_at(9), None);
    }

    #[test]
    fn generations_wrap_inside_their_bits_and_keep_the_session_bit()
    {
        let mut slots: Slots<u32, 1> = Slots {
            entries: [None],
            generations: [GENERATION_MASK],
        };
        let key = slots.insert(1).unwrap();
        assert_eq!(key, SESSION_KEY_BIT);
        assert_eq!(Key::of(key), Key::Session(key));
        assert_eq!(slots.get(key), Some(&1));
    }

    #[test]
    fn a_key_without_the_session_bit_is_a_jobs_badge()
    {
        assert_eq!(Key::of(0x1234), Key::Job(0x1234));
        assert_eq!(Key::of(u64::MAX), Key::Session(u64::MAX));
    }

    #[test]
    fn pages_cover_the_walk_once_and_their_cursor_advances()
    {
        // A walk of seven entries, in pages of three.
        let mut seen = Vec::new();
        let mut cursor = 0;
        loop
        {
            let mut page = Page::new(cursor, 3);
            for entry in 0..7
            {
                match page.place()
                {
                    Place::Skip => assert!(entry < cursor),
                    Place::Take(index) => seen.push((cursor, index, entry)),
                    Place::Full => break,
                }
            }
            let count = page.count();
            if count < 3
            {
                assert!(!page.is_full());
                break;
            }
            assert!(page.next_cursor() > cursor);
            cursor = page.next_cursor();
        }
        let entries: Vec<u64> = seen.iter().map(|&(_, _, e)| e).collect();
        assert_eq!(entries, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(seen.get(3), Some(&(3, 0, 3)));
    }

    #[test]
    fn a_cursor_past_the_walk_gives_an_empty_page()
    {
        let mut page = Page::new(4, 3);
        for _ in 0..2
        {
            assert_eq!(page.place(), Place::Skip);
        }
        assert_eq!(page.count(), 0);
        assert_eq!(page.next_cursor(), 4);
    }

    #[test]
    fn session_names_spell_the_slot_in_decimal()
    {
        let mut buf = [0u8; SESSION_NAME_MAX];
        assert_eq!(session_name(0, &mut buf), b"session 0");
        assert_eq!(session_name(15, &mut buf), b"session 15");
        assert_eq!(session_name(u32::MAX, &mut buf), b"session 4294967295");
    }
}
