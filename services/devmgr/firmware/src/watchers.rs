// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/watchers.rs

//! The watchers of one device class: the Notification caps devmgr signals
//! when the class gains a served driver or one is withdrawn
//! (`devmgr_labels::WATCH_CLASS`,
//! [docs/driver-binding.md](../../../../docs/driver-binding.md) § Device
//! Classes).
//!
//! A class holds at most [`MAX_CLASS_WATCHERS`]. The list holds cap handles
//! only and makes no syscall: the caller tells it which watchers are gone,
//! and releases the cap of each one it drops.

extern crate alloc;

use alloc::vec::Vec;

pub use ipc::devmgr_labels::MAX_CLASS_WATCHERS;

/// Why [`Watchers::add`] refused a watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchError
{
    /// The class holds [`MAX_CLASS_WATCHERS`] watchers none of which is
    /// gone, or the list cannot grow.
    Full,
    /// The class slot names no class ([`crate::classes::Classes::watch`]).
    NoClass,
}

/// The watchers of one class, in registration order.
#[derive(Default)]
pub struct Watchers
{
    caps: Vec<u64>,
}

impl Watchers
{
    /// A class no one watches.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { caps: Vec::new() }
    }

    /// Add the watcher `cap`. When the class already holds
    /// [`MAX_CLASS_WATCHERS`], first drop each watcher `gone` holds for,
    /// which releases its cap.
    ///
    /// # Errors
    /// [`WatchError::Full`] when no room is left; `cap` is not recorded and
    /// stays the caller's.
    pub fn add(&mut self, cap: u64, gone: impl FnMut(u64) -> bool) -> Result<(), WatchError>
    {
        if self.caps.len() >= MAX_CLASS_WATCHERS
        {
            self.drop_gone(gone);
        }
        if self.caps.len() >= MAX_CLASS_WATCHERS || self.caps.try_reserve(1).is_err()
        {
            return Err(WatchError::Full);
        }
        self.caps.push(cap);
        Ok(())
    }

    /// Visit every watcher: `signal` signals one and returns whether it
    /// stays, or releases one that is gone and returns `false`, which drops
    /// it.
    pub fn signal(&mut self, mut signal: impl FnMut(u64) -> bool)
    {
        self.caps.retain(|&cap| signal(cap));
    }

    /// Drop each watcher `gone` holds for, which releases its cap.
    pub fn drop_gone(&mut self, mut gone: impl FnMut(u64) -> bool)
    {
        self.caps.retain(|&cap| !gone(cap));
    }

    /// The watchers held.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.caps.len()
    }

    /// Whether no one watches the class.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.caps.is_empty()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn filled() -> Watchers
    {
        let mut w = Watchers::new();
        for cap in 1..=MAX_CLASS_WATCHERS as u64
        {
            assert_eq!(w.add(cap, |_| panic!("no sweep below the bound")), Ok(()));
        }
        w
    }

    #[test]
    fn a_registration_past_the_bound_is_refused_while_every_watcher_lives()
    {
        let mut w = filled();
        let mut asked = 0;
        assert_eq!(
            w.add(100, |_| {
                asked += 1;
                false
            }),
            Err(WatchError::Full)
        );
        assert_eq!(asked, MAX_CLASS_WATCHERS);
        assert_eq!(w.len(), MAX_CLASS_WATCHERS);
    }

    #[test]
    fn a_full_class_drops_its_gone_watchers_to_admit_one()
    {
        let mut w = filled();
        let mut released = Vec::new();
        assert_eq!(
            w.add(100, |cap| {
                let gone = cap % 2 == 0;
                if gone
                {
                    released.push(cap);
                }
                gone
            }),
            Ok(())
        );
        assert_eq!(released, [2, 4, 6, 8]);
        let mut held = Vec::new();
        w.signal(|cap| {
            held.push(cap);
            true
        });
        assert_eq!(held, [1, 3, 5, 7, 100]);
    }

    #[test]
    fn a_signal_drops_the_watchers_it_finds_gone()
    {
        let mut w = Watchers::new();
        for cap in [10, 11, 12]
        {
            w.add(cap, |_| false).unwrap();
        }
        let mut signalled = Vec::new();
        w.signal(|cap| {
            signalled.push(cap);
            cap != 11
        });
        assert_eq!(signalled, [10, 11, 12]);
        assert_eq!(w.len(), 2);
        w.drop_gone(|cap| cap == 10);
        assert_eq!(w.len(), 1);
        w.drop_gone(|_| true);
        assert!(w.is_empty());
    }
}
