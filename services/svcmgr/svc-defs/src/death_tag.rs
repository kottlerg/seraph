// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/death_tag.rs

//! The correlator svcmgr binds every death observer of a supervised service
//! with, and the rule that routes a death post by it.
//!
//! A supervised service has two observers per instance: one on its main
//! thread, and one on its address space, which the first terminal end of any
//! of its threads, a fault or an exit, posts. Both carry the same [`DeathTag`]:
//! the service's slot in svcmgr's table and the instance the observer was bound
//! for. The specification is `services/svcmgr/docs/restart-protocol.md` § Death
//! detection.

/// The slot and instance a death post names.
///
/// Packed into the correlator word as `(instance << 32) | slot`. The kernel
/// treats the word as opaque, and only svcmgr's own death queues receive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeathTag
{
    /// The service's slot in svcmgr's service table.
    pub slot: u32,
    /// The instance of the slot's service the observer was bound for: `0` for
    /// the first, one more for each restart (wrapping).
    pub instance: u32,
}

impl DeathTag
{
    /// The tag of instance `instance` of the service at `slot`; `None` when
    /// `slot` does not fit the tag's 32-bit slot field.
    #[must_use]
    pub fn new(slot: usize, instance: u32) -> Option<Self>
    {
        Some(Self {
            slot: u32::try_from(slot).ok()?,
            instance,
        })
    }

    /// The correlator word an observer is bound with.
    #[must_use]
    pub const fn correlator(self) -> u64
    {
        ((self.instance as u64) << 32) | self.slot as u64
    }

    /// The tag a post's correlator word carries.
    #[must_use]
    pub const fn from_correlator(correlator: u64) -> Self
    {
        Self {
            // The low half is the slot and the high half the instance, by
            // construction in `correlator`.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "keeps the low 32 bits: the slot"
            )]
            slot: correlator as u32,
            instance: (correlator >> 32) as u32,
        }
    }

    /// The slot as a table index.
    #[must_use]
    pub fn index(self) -> usize
    {
        // A `u32` fits a `usize` on every target svcmgr builds for (64-bit).
        usize::try_from(self.slot).unwrap_or(usize::MAX)
    }
}

/// Whether a death post carrying `tag` is the death of the service its slot
/// supervises now: the slot is active and its current instance is the one the
/// post names. Any other post is a dead instance's, already routed: the second
/// post of a fault that both observers report, or a post a resync routed
/// before it arrived. Such a post is dropped.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`active` is whether the slot supervises a service now, which the rule tests"
)]
pub fn routes(tag: DeathTag, active: bool, current_instance: u32) -> bool
{
    active && tag.instance == current_instance
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_correlator_round_trips_the_slot_and_instance()
    {
        for (slot, instance) in [
            (0, 0),
            (7, 1),
            (u32::MAX as usize, u32::MAX),
            (3, 0x8000_0000),
        ]
        {
            let tag = DeathTag::new(slot, instance).expect("slot fits");
            assert_eq!(DeathTag::from_correlator(tag.correlator()), tag);
            assert_eq!(tag.index(), slot);
        }
    }

    #[test]
    fn the_first_instance_correlator_is_the_slot()
    {
        assert_eq!(DeathTag::new(5, 0).map(DeathTag::correlator), Some(5));
    }

    #[test]
    fn a_slot_past_32_bits_has_no_tag()
    {
        assert_eq!(DeathTag::new(1usize << 32, 0), None);
    }

    #[test]
    fn a_post_routes_only_for_the_current_instance_of_an_active_slot()
    {
        let tag = DeathTag::new(2, 4).expect("slot fits");
        assert!(routes(tag, true, 4));
        assert!(!routes(tag, true, 5));
        assert!(!routes(tag, false, 4));
    }

    #[test]
    fn a_fault_both_observers_report_routes_once()
    {
        // A main-thread fault that is the space's first terminal fault posts
        // the same tag to both observers. The first post routes and the
        // restart moves the slot to the next instance; the second is dropped.
        let tag = DeathTag::new(1, 0).expect("slot fits");
        let mut instance = 0u32;
        let mut routed = 0;
        for _ in 0..2
        {
            if routes(tag, true, instance)
            {
                routed += 1;
                instance = instance.wrapping_add(1);
            }
        }
        assert_eq!(routed, 1);
    }
}
