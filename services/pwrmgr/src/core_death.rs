// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/core_death.rs

//! The entries of the core-death queue: the event queue svcmgr's own death
//! observers and those it binds on memmgr and procmgr post to, of which svcmgr
//! serves pwrmgr a receive-only derivation (docs/supervision.md § Core Set
//! and System Death). Each entry carries its member's correlator
//! (`ipc::pwrmgr_labels::CORE_DEATH_*`), with
//! `ipc::pwrmgr_labels::CORE_DEATH_ADDRESS_SPACE` set on an address-space
//! observer's, and the exit reason.
//!
//! An entry states one end the kernel posted, not a process's reason: a
//! member's main-thread end and its address space's first terminal end can
//! carry different reasons, and nothing gives a core member one reason
//! (docs/process-lifecycle.md § Exit reason), so pwrmgr logs each entry as
//! the end it is.

use ipc::pwrmgr_labels;

/// Entries the queue can hold, and so [`Deaths`] keeps: one main-thread and
/// one address-space observer for each of the three members, each posting
/// once in its life (svcmgr's `CORE_DEATH_CAPACITY`).
pub const ENTRIES_MAX: usize = 6;

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
    /// The member whose observers post `correlator`, with or without
    /// `CORE_DEATH_ADDRESS_SPACE`; `None` for a value no observer is bound
    /// with.
    #[must_use]
    pub const fn from_correlator(correlator: u64) -> Option<Self>
    {
        match correlator & !pwrmgr_labels::CORE_DEATH_ADDRESS_SPACE
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

/// Which end of a member an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End
{
    /// Its main thread's own end: an exit or a terminal fault of that
    /// thread, `sys_thread_exit` included, which ends no address space.
    MainThread,
    /// Its address space's first terminal end, a fault or a
    /// `sys_aspace_exit` of any of its threads.
    AddressSpace,
}

impl End
{
    /// The end's name, for the log.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::MainThread => "its main thread ended",
            Self::AddressSpace => "its address space ended",
        }
    }
}

/// One entry of the queue: the member, when its correlator names one, the
/// end it is, and the exit reason the kernel posted with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreDeath
{
    pub member: Option<CoreMember>,
    pub end: End,
    pub exit_reason: u64,
}

impl CoreDeath
{
    /// Decode an entry from its correlator and exit reason.
    #[must_use]
    pub const fn decode(correlator: u64, exit_reason: u64) -> Self
    {
        let end = if correlator & pwrmgr_labels::CORE_DEATH_ADDRESS_SPACE == 0
        {
            End::MainThread
        }
        else
        {
            End::AddressSpace
        };
        Self {
            member: CoreMember::from_correlator(correlator),
            end,
            exit_reason,
        }
    }
}

/// The entries drained from the queue, in the order they were posted, at
/// most [`ENTRIES_MAX`]. A fixed array, so a drain allocates nothing and the
/// power-off can run it under the armed guard ([`crate::guard`]).
#[derive(Clone, Copy, Debug)]
pub struct Deaths
{
    entries: [Option<CoreDeath>; ENTRIES_MAX],
    len: usize,
}

impl Default for Deaths
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl Deaths
{
    /// No entry drained.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: [None; ENTRIES_MAX],
            len: 0,
        }
    }

    /// Drain the queue through `next`, which yields each entry's correlator
    /// and exit reason until the queue is empty, and keep each entry after
    /// those drained before, while there is room. Allocates nothing.
    pub fn drain(&mut self, mut next: impl FnMut() -> Option<(u64, u64)>)
    {
        while let Some((correlator, exit_reason)) = next()
        {
            if let Some(slot) = self.entries.get_mut(self.len)
            {
                *slot = Some(CoreDeath::decode(correlator, exit_reason));
                self.len = self.len.saturating_add(1);
            }
        }
    }

    /// The first entry drained: the core death that powers the system off.
    /// `None` when none was.
    #[must_use]
    pub fn first(&self) -> Option<CoreDeath>
    {
        self.entries.first().copied().flatten()
    }

    /// Every entry drained of `member`, in the order they were posted.
    pub fn of(&self, member: Option<CoreMember>) -> impl Iterator<Item = CoreDeath> + '_
    {
        self.entries
            .iter()
            .flatten()
            .copied()
            .filter(move |d| d.member == member)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use pwrmgr_labels::CORE_DEATH_ADDRESS_SPACE as SPACE;

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
            assert_eq!(
                CoreMember::from_correlator(correlator | SPACE),
                Some(member)
            );
        }
        assert_eq!(CoreMember::from_correlator(3), None);
        assert_eq!(CoreMember::from_correlator(3 | SPACE), None);
        assert_eq!(CoreMember::from_correlator(u64::MAX), None);
    }

    // Defect caught: an address-space entry read as the main thread's, or the
    // reverse, so the log names an end the kernel did not post (#1451: a
    // main-thread `sys_thread_exit` posting 0 ahead of a worker's fault).
    #[test]
    fn the_flag_names_the_end()
    {
        let thread = CoreDeath::decode(pwrmgr_labels::CORE_DEATH_MEMMGR, 0);
        assert_eq!(thread.member, Some(CoreMember::Memmgr));
        assert_eq!(thread.end, End::MainThread);
        assert_eq!(thread.exit_reason, 0);
        let space = CoreDeath::decode(pwrmgr_labels::CORE_DEATH_MEMMGR | SPACE, 0x100E);
        assert_eq!(space.member, Some(CoreMember::Memmgr));
        assert_eq!(space.end, End::AddressSpace);
        assert_eq!(space.exit_reason, 0x100E);
    }

    // Defect caught: a drain whose first entry is not the first posted, that
    // loses an entry posted after an earlier drain, or that mixes another
    // member's entries into a member's.
    #[test]
    fn drains_keep_every_entry_in_order_and_members_apart()
    {
        let mut deaths = Deaths::new();
        assert_eq!(deaths.first(), None);
        let mut posted = [(1, 0), (2 | SPACE, 0x2000)].into_iter();
        deaths.drain(|| posted.next());
        // A post that arrived after the first drain.
        let mut late = Some((1 | SPACE, 0x100E));
        deaths.drain(|| late.take());

        let first = CoreDeath::decode(1, 0);
        assert_eq!(deaths.first(), Some(first));
        let memmgr: Vec<_> = deaths.of(Some(CoreMember::Memmgr)).collect();
        assert_eq!(memmgr, [first, CoreDeath::decode(1 | SPACE, 0x100E)]);
        let procmgr: Vec<_> = deaths.of(Some(CoreMember::Procmgr)).collect();
        assert_eq!(procmgr, [CoreDeath::decode(2 | SPACE, 0x2000)]);
        assert_eq!(deaths.of(Some(CoreMember::Svcmgr)).count(), 0);
    }

    // Defect caught: a drain that stops at the array's end, leaving entries on
    // the queue to wake pwrmgr again, or that overruns the array.
    #[test]
    fn a_full_drain_empties_the_queue()
    {
        let mut deaths = Deaths::new();
        let mut taken = 0;
        let mut left = ENTRIES_MAX + 2;
        deaths.drain(|| {
            (left > 0).then(|| {
                left -= 1;
                taken += 1;
                (9, 0x30)
            })
        });
        assert_eq!(taken, ENTRIES_MAX + 2);
        assert_eq!(deaths.of(None).count(), ENTRIES_MAX);
        assert_eq!(
            deaths.first(),
            Some(CoreDeath {
                member: None,
                end: End::MainThread,
                exit_reason: 0x30
            })
        );
    }
}
