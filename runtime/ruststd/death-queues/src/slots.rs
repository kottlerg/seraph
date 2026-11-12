// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/death-queues/src/slots.rs

//! The slot registry of ruststd's thread reaper.
//!
//! Every spawned thread binds a death observer whose correlator names a slot
//! of a [`Registry`] and the slot's generation. A joined thread frees its own
//! slot ([`Registry::release`]); a detached one leaves its resources in the
//! slot ([`Registry::detach`]) until its death post arrives
//! ([`Registry::death`]), which hands them back to be reclaimed. The
//! generation makes a stale post, for a slot since released and reused, a
//! no-op. The table grows one slot at a time when every slot is occupied, so
//! the number of concurrently bound threads is bounded only by memory and by
//! the slot index's 32 bits. The registry holds no lock and makes no
//! syscall: ruststd serialises it and does the binding and the reclaiming.

// When this crate is compiled as a std dep via rustc-dep-of-std, the
// crate root is `no_core` and the prelude reaches only the root module;
// submodules import it themselves. Harmless no-op otherwise.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use alloc::vec::Vec;

/// The `u64` correlator a death observer is bound with: `slot` in the high
/// 32 bits, `generation` in the low 32. [`split`] reverses it.
#[must_use]
pub const fn correlator(slot: u32, generation: u32) -> u64
{
    ((slot as u64) << 32) | generation as u64
}

/// The slot and generation a death post's correlator names ([`correlator`]).
#[must_use]
pub const fn split(correlator: u64) -> (u32, u32)
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the high and low halves of a u64 each fit a u32"
    )]
    let parts = ((correlator >> 32) as u32, correlator as u32);
    parts
}

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State
{
    /// No occupant.
    Vacant,
    /// Bound, its thread's handle still held (joinable); the resources live
    /// in the handle.
    Reserved,
    /// The handle was dropped (detached); the resources live in the slot,
    /// awaiting the death post.
    Detached,
}

/// One registry slot.
struct Slot<T>
{
    state: State,
    generation: u32,
    /// Set when a death post arrives while the slot is still `Reserved`
    /// (the thread died before its handle was joined or detached), so
    /// [`Registry::detach`] reclaims at once instead of waiting for a post
    /// that already came.
    died: bool,
    res: Option<T>,
}

impl<T> Slot<T>
{
    const fn vacant() -> Self
    {
        Self {
            state: State::Vacant,
            generation: 0,
            died: false,
            res: None,
        }
    }
}

/// What [`Registry::detach`] did with a detached thread's resources.
#[derive(Debug, PartialEq, Eq)]
pub enum Detached<T>
{
    /// The thread had already died; the caller reclaims the resources now.
    Reclaim(T),
    /// The slot holds them until the thread's death post.
    Held,
    /// The slot was not the caller's (released or reused under it): the
    /// resources cannot be reclaimed safely, and the caller leaks them.
    Leak(T),
}

/// Why [`Registry::reserve`] gave no slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError
{
    /// Every slot is occupied and the table's allocation could not grow.
    NoMemory,
    /// Every slot is occupied and the table already holds its most slots
    /// (`u32::MAX`, unless [`Registry::with_max_slots`] set fewer).
    IndexExhausted,
}

/// The reaper's slots, the indices of the vacant ones, and the generation
/// the next reserved slot takes.
pub struct Registry<T>
{
    next_gen: u32,
    /// The most slots the table grows to.
    max_slots: u32,
    slots: Vec<Slot<T>>,
    /// Indices of vacant slots, popped by [`Registry::reserve`] before the
    /// table grows. Its capacity is kept at least the table's length, so a
    /// slot freed by [`Registry::release`] or [`Registry::death`] is
    /// recorded without allocating.
    free: Vec<u32>,
}

impl<T> Registry<T>
{
    /// An empty registry: no slot until the first [`Self::reserve`], and
    /// at most `u32::MAX` slots.
    #[must_use]
    pub const fn new() -> Self
    {
        Self::with_max_slots(u32::MAX)
    }

    /// An empty registry that grows to at most `max_slots` slots.
    #[must_use]
    pub const fn with_max_slots(max_slots: u32) -> Self
    {
        Self {
            next_gen: 1,
            max_slots,
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Slots the table holds, occupied or not.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.slots.len()
    }

    /// Whether the table holds no slot.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.slots.is_empty()
    }

    /// Reserve a slot for a thread being bound: a vacant one (the most
    /// recently freed), or a new one appended when every slot is occupied.
    /// Returns its index and generation.
    ///
    /// # Errors
    /// [`ReserveError::NoMemory`] when every slot is occupied and the table
    /// cannot grow; [`ReserveError::IndexExhausted`] when every slot is
    /// occupied and the table already holds its most slots. The registry is
    /// unchanged on an error.
    pub fn reserve(&mut self) -> Result<(u32, u32), ReserveError>
    {
        let slot = if let Some(slot) = self.free.pop()
        {
            slot
        }
        else
        {
            let slot = u32::try_from(self.slots.len())
                .ok()
                .filter(|&slot| slot < self.max_slots)
                .ok_or(ReserveError::IndexExhausted)?;
            self.slots
                .try_reserve(1)
                .map_err(|_| ReserveError::NoMemory)?;
            // Room for this slot's index in `free`, so freeing it never
            // allocates. `free` never holds more indices than there are
            // slots, and `slots.len()` is below `max_slots`, so neither
            // operation saturates.
            self.free
                .try_reserve(
                    self.slots
                        .len()
                        .saturating_add(1)
                        .saturating_sub(self.free.len()),
                )
                .map_err(|_| ReserveError::NoMemory)?;
            self.slots.push(Slot::vacant());
            slot
        };
        // A slot from `free` was vacated in place, and a new one was just
        // pushed, so the index is in range.
        let entry = self
            .slots
            .get_mut(slot as usize)
            .ok_or(ReserveError::IndexExhausted)?;
        let generation = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        *entry = Slot {
            state: State::Reserved,
            generation,
            died: false,
            res: None,
        };
        Ok((slot, generation))
    }

    /// Make slot `slot` vacant and record it as free.
    fn vacate(&mut self, slot: u32)
    {
        // Every caller found `slot` through `slot_mut`, so it is in range.
        let Some(entry) = self.slots.get_mut(slot as usize)
        else
        {
            return;
        };
        *entry = Slot::vacant();
        // `free`'s capacity covers every slot (`reserve`), so this does not
        // allocate.
        self.free.push(slot);
    }

    /// Free `slot` for a joined thread (or one never started), whose
    /// resources the caller reclaims itself. A later death post for it is
    /// ignored. A slot of another generation, or vacant, is left alone.
    pub fn release(&mut self, slot: u32, generation: u32)
    {
        if self
            .slot_mut(slot, generation)
            .is_some_and(|s| s.state != State::Vacant)
        {
            self.vacate(slot);
        }
    }

    /// Hand a detached thread's resources to `slot` (or a joined thread's
    /// whose join wait failed). See [`Detached`] for the outcomes.
    pub fn detach(&mut self, slot: u32, generation: u32, res: T) -> Detached<T>
    {
        let Some(s) = self.slot_mut(slot, generation)
        else
        {
            return Detached::Leak(res);
        };
        if s.state != State::Reserved
        {
            return Detached::Leak(res);
        }
        if s.died
        {
            self.vacate(slot);
            return Detached::Reclaim(res);
        }
        s.state = State::Detached;
        s.res = Some(res);
        Detached::Held
    }

    /// A death post carrying `correlator` arrived. Returns the resources of
    /// a detached thread, which the caller reclaims, and frees its slot; for
    /// a thread whose handle is still held, marks the slot so its
    /// [`Self::detach`] reclaims at once. A stale or unknown correlator does
    /// nothing.
    pub fn death(&mut self, correlator: u64) -> Option<T>
    {
        let (slot, generation) = split(correlator);
        let s = self.slot_mut(slot, generation)?;
        match s.state
        {
            State::Detached =>
            {
                let res = s.res.take();
                self.vacate(slot);
                res
            }
            State::Reserved =>
            {
                s.died = true;
                None
            }
            State::Vacant => None,
        }
    }

    /// The slot at `slot` when it carries `generation`.
    fn slot_mut(&mut self, slot: u32, generation: u32) -> Option<&mut Slot<T>>
    {
        let s = self.slots.get_mut(usize::try_from(slot).ok()?)?;
        (s.generation == generation).then_some(s)
    }
}

impl<T> Default for Registry<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_correlator_carries_a_full_slot_index_and_generation()
    {
        for (slot, generation) in [(0, 1), (63, 7), (64, 9), (u32::MAX, u32::MAX)]
        {
            assert_eq!(split(correlator(slot, generation)), (slot, generation));
        }
    }

    #[test]
    fn the_table_grows_past_sixty_four_concurrent_threads()
    {
        let mut reg = Registry::<u32>::new();
        let reserved: Vec<_> = (0..200).map(|_| reg.reserve().expect("room")).collect();
        let slots: Vec<u32> = reserved.iter().map(|&(s, _)| s).collect();
        assert_eq!(slots, (0..200).collect::<Vec<_>>());
        assert_eq!(reg.len(), 200);
    }

    #[test]
    fn a_released_slot_is_reused_before_the_table_grows()
    {
        let mut reg = Registry::<u32>::new();
        let (a, ga) = reg.reserve().expect("room");
        let (_b, _) = reg.reserve().expect("room");
        reg.release(a, ga);
        let (c, gc) = reg.reserve().expect("room");
        assert_eq!(c, a);
        assert_ne!(gc, ga);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn a_detached_thread_is_reclaimed_by_its_death_post()
    {
        let mut reg = Registry::new();
        let (slot, generation) = reg.reserve().expect("room");
        assert_eq!(reg.detach(slot, generation, 42), Detached::Held);
        assert_eq!(reg.death(correlator(slot, generation)), Some(42));
        // The slot is free again; a repeated post does nothing.
        assert_eq!(reg.death(correlator(slot, generation)), None);
    }

    #[test]
    fn a_thread_dead_before_its_detach_is_reclaimed_at_the_detach()
    {
        let mut reg = Registry::new();
        let (slot, generation) = reg.reserve().expect("room");
        assert_eq!(reg.death(correlator(slot, generation)), None);
        assert_eq!(reg.detach(slot, generation, 7), Detached::Reclaim(7));
    }

    #[test]
    fn a_stale_post_for_a_reused_slot_does_nothing()
    {
        let mut reg = Registry::new();
        let (slot, old) = reg.reserve().expect("room");
        reg.release(slot, old);
        let (again, new) = reg.reserve().expect("room");
        assert_eq!(again, slot);
        assert_eq!(reg.detach(again, new, 5), Detached::Held);
        assert_eq!(reg.death(correlator(slot, old)), None);
        assert_eq!(reg.death(correlator(again, new)), Some(5));
    }

    #[test]
    fn a_detach_into_a_slot_not_the_callers_leaks()
    {
        let mut reg = Registry::new();
        let (slot, generation) = reg.reserve().expect("room");
        reg.release(slot, generation);
        assert_eq!(reg.detach(slot, generation, 3), Detached::Leak(3));
        assert_eq!(reg.detach(99, 1, 4), Detached::Leak(4));
    }

    #[test]
    fn a_release_of_another_generation_leaves_the_slot_alone()
    {
        let mut reg = Registry::new();
        let (slot, generation) = reg.reserve().expect("room");
        reg.release(slot, generation.wrapping_add(1));
        assert_eq!(reg.detach(slot, generation, 8), Detached::Held);
    }

    #[test]
    fn a_generation_zero_post_does_nothing_to_a_vacant_slot()
    {
        // A vacant slot carries generation 0; a post naming it must not
        // reclaim or mark anything.
        let mut reg = Registry::<u32>::new();
        let (slot, generation) = reg.reserve().expect("room");
        reg.release(slot, generation);
        assert_eq!(reg.death(correlator(slot, 0)), None);
        let (again, fresh) = reg.reserve().expect("room");
        assert_eq!(again, slot);
        assert_eq!(reg.detach(again, fresh, 6), Detached::Held);
    }

    #[test]
    fn a_post_after_a_died_thread_is_released_does_nothing()
    {
        // The thread died while its handle was held, then was joined (its
        // slot released): a repeated post for it must be stale.
        let mut reg = Registry::<u32>::new();
        let (slot, generation) = reg.reserve().expect("room");
        assert_eq!(reg.death(correlator(slot, generation)), None);
        reg.release(slot, generation);
        assert_eq!(reg.death(correlator(slot, generation)), None);
        let (again, fresh) = reg.reserve().expect("room");
        assert_eq!(again, slot);
        assert_eq!(reg.detach(again, fresh, 9), Detached::Held);
    }

    #[test]
    fn slots_freed_by_a_post_or_a_reclaiming_detach_are_reused_before_growth()
    {
        let mut reg = Registry::<u32>::new();
        // Slot a: detached, then freed by its death post.
        let (a, ga) = reg.reserve().expect("room");
        // Slot b: dead first, then freed by its detach (Reclaim).
        let (b, gb) = reg.reserve().expect("room");
        assert_eq!(reg.detach(a, ga, 1), Detached::Held);
        assert_eq!(reg.death(correlator(a, ga)), Some(1));
        assert_eq!(reg.death(correlator(b, gb)), None);
        assert_eq!(reg.detach(b, gb, 2), Detached::Reclaim(2));
        let mut reused = [
            reg.reserve().expect("room").0,
            reg.reserve().expect("room").0,
        ];
        reused.sort_unstable();
        assert_eq!(reused, [a, b]);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn a_full_table_at_its_most_slots_refuses_a_reservation()
    {
        let mut reg = Registry::<u32>::with_max_slots(2);
        let (a, ga) = reg.reserve().expect("room");
        reg.reserve().expect("room");
        assert_eq!(reg.reserve(), Err(ReserveError::IndexExhausted));
        assert_eq!(reg.len(), 2);
        // A freed slot is still handed out.
        reg.release(a, ga);
        assert_eq!(reg.reserve().map(|(slot, _)| slot), Ok(a));
    }

    #[test]
    fn a_table_that_cannot_grow_refuses_a_reservation()
    {
        // A slot larger than any host's user address space (at most 2^56
        // bytes, under 5-level paging or Sv57) has no allocation under any
        // overcommit policy: the table's growth fails.
        let mut reg = Registry::<[u8; 1 << 58]>::new();
        assert_eq!(reg.reserve(), Err(ReserveError::NoMemory));
        assert!(reg.is_empty());
    }

    #[test]
    fn an_unknown_correlator_does_nothing()
    {
        let mut reg = Registry::<u32>::new();
        assert_eq!(reg.death(correlator(5, 1)), None);
        assert!(reg.is_empty());
    }
}
