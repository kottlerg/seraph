// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/dma_holds.rs

//! The memory reclaims procmgr holds back for the children created with
//! `procmgr_labels::CREATE_DMA_HOLD`.
//!
//! A started child whose creator set the flag is torn down as every child is,
//! but its `memmgr_labels::PROCESS_DIED` waits until the creator sends
//! `procmgr_labels::RELEASE_HOLD` on the child's release token: a device the
//! child drove may still be writing the child's frames until the creator has
//! confirmed its DMA stopped (`docs/process-lifecycle.md` § Process Death).
//! [`DmaHolds`] keeps the held records and reserves the room for each when
//! its child is armed, so the teardown that parks a record never allocates;
//! [`release_target`] is the token's authority check.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::ProcessEntry;

/// The badge of the release token procmgr derives for the held child
/// `badge`: the child's process badge with
/// `procmgr_labels::HOLD_RELEASE_AUTHORITY` set. A process badge carries no
/// verb bit (`crate::badge_is_acceptable`), so the token's badge names no
/// live process.
#[must_use]
pub const fn release_token_badge(badge: u64) -> u64
{
    badge | ipc::procmgr_labels::HOLD_RELEASE_AUTHORITY
}

/// The child whose held reclaim a `RELEASE_HOLD` received with badge
/// `sender` may release: the badge with every verb bit cleared, when it
/// carries `procmgr_labels::HOLD_RELEASE_AUTHORITY`. `None` for any other
/// sender (the child's process handle, the child's own procmgr cap, or any
/// other SEND), which procmgr refuses `UNAUTHORIZED`.
#[must_use]
pub const fn release_target(sender: u64) -> Option<u64>
{
    if sender & ipc::procmgr_labels::HOLD_RELEASE_AUTHORITY == 0
    {
        None
    }
    else
    {
        Some(sender & !ipc::VERB_BIT_MASK)
    }
}

/// Why a `RELEASE_HOLD` released nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal
{
    /// The sender's badge lacks `procmgr_labels::HOLD_RELEASE_AUTHORITY`
    /// ([`release_target`]); any hold stays.
    Unauthorized,
    /// No record is held for the token's child: it is live, was never armed,
    /// was released already, or never existed.
    NotHeld,
}

/// The memmgr record of a torn-down child whose reclaim is held back: what
/// procmgr needs to send its `PROCESS_DIED` once the creator releases it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldReclaim
{
    /// The child's process badge, which its process handle carries.
    pub badge: u64,
    /// The memmgr-side badge `PROCESS_DIED` names.
    pub memmgr_badge: u64,
    /// procmgr's slot of the child's badged memmgr SEND, deleted after the
    /// `PROCESS_DIED` round trip; zero when there is none.
    pub memmgr_send_cap: u64,
}

/// The held reclaims, with room reserved for every armed child's.
///
/// Invariant: the vector's capacity is at least its length plus `armed`, so
/// [`Self::park`] pushes without growing it.
#[derive(Default)]
pub struct DmaHolds
{
    held: Vec<HeldReclaim>,
    /// Live entries whose `dma_hold` is set: each may park one record.
    armed: usize,
}

impl DmaHolds
{
    /// No held record and no armed child.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            held: Vec::new(),
            armed: 0,
        }
    }

    /// Reserve the room one more armed child's record takes when it parks.
    ///
    /// # Errors
    /// The allocation error when the heap cannot grow the records; nothing
    /// is armed then.
    pub fn arm(&mut self) -> Result<(), TryReserveError>
    {
        let armed = self.armed + 1;
        self.held.try_reserve(armed)?;
        self.armed = armed;
        Ok(())
    }

    /// Settle the reclaim of `entry`, a child just taken out of the table
    /// for its teardown. Returns `true` when the reclaim is held: the entry
    /// was armed and its child started, so a device it drove may still reach
    /// its frames, and its record is parked until [`Self::release`]. Returns
    /// `false` when procmgr sends `PROCESS_DIED` now: the entry was not
    /// armed, or its child never ran and so never touched a device.
    pub fn park(&mut self, entry: &ProcessEntry) -> bool
    {
        if !entry.dma_hold
        {
            return false;
        }
        self.armed = self.armed.saturating_sub(1);
        if !entry.started
        {
            return false;
        }
        // Room for this push was reserved when the entry was armed.
        self.held.push(HeldReclaim {
            badge: entry.badge,
            memmgr_badge: entry.memmgr_badge,
            memmgr_send_cap: entry.memmgr_send_cap,
        });
        true
    }

    /// Take the held record a `RELEASE_HOLD` received with badge `sender`
    /// names, for its `PROCESS_DIED`.
    ///
    /// # Errors
    /// [`ReleaseRefusal::Unauthorized`] when `sender` is no release token
    /// ([`release_target`]), every record left held;
    /// [`ReleaseRefusal::NotHeld`] when no record is held for the token's
    /// child.
    pub fn release(&mut self, sender: u64) -> Result<HeldReclaim, ReleaseRefusal>
    {
        let badge = release_target(sender).ok_or(ReleaseRefusal::Unauthorized)?;
        let at = self
            .held
            .iter()
            .position(|r| r.badge == badge)
            .ok_or(ReleaseRefusal::NotHeld)?;
        Ok(self.held.swap_remove(at))
    }

    /// Whether a record is held for `badge`.
    #[must_use]
    pub fn holds(&self, badge: u64) -> bool
    {
        self.held.iter().any(|r| r.badge == badge)
    }

    /// Number of held records.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.held.len()
    }

    /// Whether no record is held.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.held.is_empty()
    }

    /// Number of armed children, for the table's tests.
    #[cfg(test)]
    pub(crate) fn armed(&self) -> usize
    {
        self.armed
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn entry(badge: u64, dma_hold: bool, started: bool) -> ProcessEntry
    {
        ProcessEntry {
            badge,
            aspace_cap: 0,
            cspace_cap: 0,
            thread_cap: 0,
            pi_memory_cap: 0,
            tls_memory_cap: 0,
            argv_env_memory_cap: 0,
            memmgr_send_cap: 41,
            memmgr_badge: badge ^ 0xFF,
            namespace_override: 0,
            cwd_override: 0,
            band_max: 0,
            entry_point: 0,
            tls_base_va: 0,
            stack_top_vaddr: 0,
            process_info_va: 0,
            started,
            dma_hold,
            no_debug: false,
            image: crate::ImageSpan::default(),
        }
    }

    #[test]
    fn an_unarmed_child_is_reclaimed_at_its_teardown()
    {
        let mut holds = DmaHolds::new();
        assert!(!holds.park(&entry(7, false, true)));
        assert!(holds.is_empty());
        assert_eq!(
            holds.release(release_token_badge(7)),
            Err(ReleaseRefusal::NotHeld)
        );
    }

    #[test]
    fn an_armed_started_child_is_held_until_released_once()
    {
        let mut holds = DmaHolds::new();
        holds.arm().unwrap();
        assert!(holds.park(&entry(7, true, true)));
        assert!(holds.holds(7));
        assert_eq!(
            holds.release(release_token_badge(7)),
            Ok(HeldReclaim {
                badge: 7,
                memmgr_badge: 7 ^ 0xFF,
                memmgr_send_cap: 41,
            })
        );
        assert!(!holds.holds(7));
        assert_eq!(
            holds.release(release_token_badge(7)),
            Err(ReleaseRefusal::NotHeld)
        );
    }

    #[test]
    fn a_release_without_the_token_bit_is_refused_and_the_hold_stays()
    {
        // The process handle and the child's own procmgr cap carry the plain
        // process badge; logd's cap carries another verb bit; an un-badged
        // SEND carries 0. None of them may release the hold.
        let badge = 0x0000_0123_0000_0040;
        let mut holds = DmaHolds::new();
        holds.arm().unwrap();
        assert!(holds.park(&entry(badge, true, true)));
        for sender in [
            badge,
            badge | ipc::procmgr_labels::DEATH_EQ_AUTHORITY,
            ipc::procmgr_labels::DEATH_EQ_AUTHORITY,
            0,
        ]
        {
            assert_eq!(holds.release(sender), Err(ReleaseRefusal::Unauthorized));
            assert!(holds.holds(badge));
        }
        assert_eq!(
            holds.release(release_token_badge(badge)).map(|r| r.badge),
            Ok(badge)
        );
    }

    #[test]
    fn a_token_names_exactly_the_child_it_was_derived_for()
    {
        // Every bit a process badge may carry survives the split, and no
        // verb bit leaks into the child the token names.
        let verbs = ipc::VERB_BIT_MASK;
        for badge in [16, 0x0000_0001_0000_0010, !verbs, !verbs & !0xF]
        {
            let token = release_token_badge(badge);
            assert_ne!(token, badge);
            assert_eq!(release_target(token), Some(badge));
        }
        assert_eq!(release_target(16), None);
        // A token minted with further verb bits still names only its child.
        assert_eq!(
            release_target(release_token_badge(16) | ipc::procmgr_labels::DEATH_EQ_AUTHORITY),
            Some(16)
        );
    }

    #[test]
    fn an_armed_child_that_never_started_is_reclaimed_at_once()
    {
        let mut holds = DmaHolds::new();
        holds.arm().unwrap();
        assert!(!holds.park(&entry(7, true, false)));
        assert!(holds.is_empty());
    }

    #[test]
    fn a_release_before_the_teardown_finds_nothing_and_the_teardown_still_holds()
    {
        // The creator's release that overtakes procmgr's reap of the child
        // must not let the reap free the frames.
        let mut holds = DmaHolds::new();
        holds.arm().unwrap();
        assert_eq!(
            holds.release(release_token_badge(7)),
            Err(ReleaseRefusal::NotHeld)
        );
        assert!(holds.park(&entry(7, true, true)));
        assert!(holds.release(release_token_badge(7)).is_ok());
    }

    #[test]
    fn every_armed_child_parks_without_growing_the_records()
    {
        let mut holds = DmaHolds::new();
        for _ in 0..5
        {
            holds.arm().unwrap();
        }
        let capacity = holds.held.capacity();
        assert!(capacity >= 5);
        for badge in 1..=5
        {
            assert!(holds.park(&entry(badge, true, true)));
        }
        assert_eq!(holds.held.capacity(), capacity);
        assert_eq!(holds.len(), 5);
    }

    #[test]
    fn a_release_takes_only_its_own_record()
    {
        let mut holds = DmaHolds::new();
        for badge in 1..=5
        {
            holds.arm().unwrap();
            assert!(holds.park(&entry(badge, true, true)));
        }
        assert_eq!(
            holds.release(release_token_badge(2)).map(|r| r.badge),
            Ok(2)
        );
        for badge in [1, 3, 4, 5]
        {
            assert!(holds.holds(badge));
        }
        assert_eq!(holds.len(), 4);
    }
}
