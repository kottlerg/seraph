// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/crash_registrant.rs

//! The registered crash service as procmgr records it: the service's thread
//! cap and the generation of its registration.
//!
//! procmgr serves `REGISTER_CRASH_SERVICE` on its request workers. A
//! registration whose reply fails is undone after the lock that guards this
//! record was released, and in between another worker may have taken the
//! registration back and accepted a new one. The generation names one
//! registration however the thread cap's slot is reused, so an undo leaves a
//! later registration alone (`services/procmgr/src/crash.rs`).

/// The current registration, if any. Kept behind procmgr's registration lock.
#[derive(Debug, Default)]
pub struct Registrant
{
    /// The registered service's thread cap in procmgr's `CSpace`; 0 while
    /// none is registered.
    thread: u64,
    /// The last registration's generation, counting from 1.
    generation: u64,
}

impl Registrant
{
    /// No service registered.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            thread: 0,
            generation: 0,
        }
    }

    /// The registered service's thread cap, 0 while none is registered.
    #[must_use]
    pub fn thread(&self) -> u64
    {
        self.thread
    }

    /// Record `thread` (nonzero) as the registered service's thread cap and
    /// return the new registration's generation.
    pub fn register(&mut self, thread: u64) -> u64
    {
        self.generation = self.generation.wrapping_add(1);
        self.thread = thread;
        self.generation
    }

    /// Forget the registration and return its thread cap, for the caller to
    /// delete; 0 when none is registered.
    pub fn take_back(&mut self) -> u64
    {
        core::mem::take(&mut self.thread)
    }

    /// Forget the registration only when it is the one `generation` names,
    /// and return its thread cap; return 0, and change nothing, when no
    /// service is registered or a later registration is.
    pub fn take_back_generation(&mut self, generation: u64) -> u64
    {
        if self.generation == generation
        {
            self.take_back()
        }
        else
        {
            0
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn an_undo_takes_back_its_own_registration()
    {
        let mut r = Registrant::new();
        let g = r.register(7);
        assert_eq!(r.thread(), 7);
        assert_eq!(r.take_back_generation(g), 7);
        assert_eq!(r.thread(), 0);
    }

    #[test]
    fn an_undo_leaves_a_later_registration_in_the_same_slot()
    {
        // A registers in slot 7; a check takes A back, and B registers with
        // a cap that reuses slot 7. A's undo must leave B registered.
        let mut r = Registrant::new();
        let a = r.register(7);
        assert_eq!(r.take_back(), 7);
        let b = r.register(7);
        assert_ne!(a, b);
        assert_eq!(r.take_back_generation(a), 0);
        assert_eq!(r.thread(), 7);
        assert_eq!(r.take_back_generation(b), 7);
    }

    #[test]
    fn an_undo_after_a_check_took_it_back_changes_nothing()
    {
        let mut r = Registrant::new();
        let g = r.register(7);
        assert_eq!(r.take_back(), 7);
        assert_eq!(r.take_back_generation(g), 0);
        assert_eq!(r.thread(), 0);
    }

    #[test]
    fn take_back_with_none_registered_returns_zero()
    {
        let mut r = Registrant::new();
        assert_eq!(r.take_back(), 0);
        assert_eq!(r.take_back_generation(0), 0);
    }
}
