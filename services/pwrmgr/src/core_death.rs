// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/core_death.rs

//! The entries of the core-death queue: the event queue svcmgr's own death
//! observers and those it binds on memmgr and procmgr post to, of which svcmgr
//! serves pwrmgr a receive-only derivation (docs/supervision.md § Core Set
//! and System Death). Each entry carries its member's correlator
//! (`ipc::pwrmgr_labels::CORE_DEATH_*`) and the exit reason.

use ipc::pwrmgr_labels;

/// A member of the core set, as its observers' correlator names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreMember
{
    Svcmgr,
    Memmgr,
    Procmgr,
}

impl CoreMember
{
    /// The member whose observers post `correlator`; `None` for a value no
    /// observer is bound with.
    #[must_use]
    pub const fn from_correlator(correlator: u64) -> Option<Self>
    {
        match correlator
        {
            pwrmgr_labels::CORE_DEATH_SVCMGR => Some(Self::Svcmgr),
            pwrmgr_labels::CORE_DEATH_MEMMGR => Some(Self::Memmgr),
            pwrmgr_labels::CORE_DEATH_PROCMGR => Some(Self::Procmgr),
            _ => None,
        }
    }

    /// The member's name, for the log.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Svcmgr => "svcmgr",
            Self::Memmgr => "memmgr",
            Self::Procmgr => "procmgr",
        }
    }
}

/// One core death: the member, when its correlator names one, and the exit
/// reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreDeath
{
    pub member: Option<CoreMember>,
    pub exit_reason: u64,
}

/// Drain the queue through `next`, which yields each entry's correlator and
/// exit reason until the queue is empty, and return the first. Every entry
/// is a core death and powers the system off; the rest are the same death's
/// second observer or a member that died after it. `None` when the queue
/// was empty. Allocates nothing, so the power-off can run it under the
/// armed guard ([`crate::guard`]).
pub fn first(mut next: impl FnMut() -> Option<(u64, u64)>) -> Option<CoreDeath>
{
    let (correlator, exit_reason) = next()?;
    while next().is_some()
    {}
    Some(CoreDeath {
        member: CoreMember::from_correlator(correlator),
        exit_reason,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a correlator decoded to the wrong member, or a value no
    // observer posts named as a member.
    #[test]
    fn each_members_correlator_names_it()
    {
        for member in [CoreMember::Svcmgr, CoreMember::Memmgr, CoreMember::Procmgr]
        {
            let correlator = match member
            {
                CoreMember::Svcmgr => pwrmgr_labels::CORE_DEATH_SVCMGR,
                CoreMember::Memmgr => pwrmgr_labels::CORE_DEATH_MEMMGR,
                CoreMember::Procmgr => pwrmgr_labels::CORE_DEATH_PROCMGR,
            };
            assert_eq!(CoreMember::from_correlator(correlator), Some(member));
        }
        assert_eq!(CoreMember::from_correlator(3), None);
        assert_eq!(CoreMember::from_correlator(u64::MAX), None);
    }

    // Defect caught: a drain that reports a later entry than the first, leaves
    // entries behind (a second wake on the same death), or reports a death
    // for an empty queue.
    #[test]
    fn the_first_entry_is_the_death_and_the_rest_are_drained()
    {
        let mut entries = [(1, 0x10), (1, 0x10), (2, 0x20)].into_iter();
        let mut taken = 0;
        let death = first(|| {
            let next = entries.next();
            taken += usize::from(next.is_some());
            next
        });
        assert_eq!(
            death,
            Some(CoreDeath {
                member: Some(CoreMember::Memmgr),
                exit_reason: 0x10
            })
        );
        assert_eq!(taken, 3);
        assert_eq!(first(|| None), None);
        // An entry whose correlator names no member is still a core death.
        assert_eq!(
            first({
                let mut once = Some((9, 0x30));
                move || once.take()
            }),
            Some(CoreDeath {
                member: None,
                exit_reason: 0x30
            })
        );
    }
}
