// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/quiesce.rs

//! The quiesce point of a process and the target of a checkpoint
//! (`procmgr_labels::QUIESCE`, `procmgr_labels::CHECKPOINT`;
//! docs/checkpoint-restore.md § Quiesce point, § Checkpoint): the state
//! procmgr keeps in each process's entry, and the checks a request makes of
//! it under the table lock.

use crate::{ProcessEntry, ProcessTable};
use ipc::procmgr_errors;

/// Whether a process may quiesce, and the point it is at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quiesce
{
    /// The process can never be restored: it was created pinned or
    /// phys-class, so `QUIESCE` refuses it (`NOT_RESTORABLE`).
    Refused,
    /// At no quiesce point.
    Idle,
    /// At the quiesce point it entered.
    At(QuiescePoint),
}

impl Quiesce
{
    /// The state a child starts in: [`Quiesce::Idle`] when it is paged and
    /// not phys-class, else [`Quiesce::Refused`]. A restore replays the
    /// captured memory into memmgr regions of a paged space, which an eager
    /// child does not have, and reproduces no physical address
    /// (docs/checkpoint-restore.md § Quiesce point).
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "the two facts a creation found, whether its pager took effect and its class, \
                  which no type of the table names"
    )]
    pub const fn for_child(paged: bool, phys: bool) -> Self
    {
        if paged && !phys
        {
            Quiesce::Idle
        }
        else
        {
            Quiesce::Refused
        }
    }
}

/// A recorded quiesce point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuiescePoint
{
    /// The restore stack pointer the process gave.
    pub restore_sp: u64,
    /// Slot in procmgr's `CSpace` of the process's Notify-only Notification,
    /// which procmgr signals once a checkpoint of the point is delivered.
    pub notify: u64,
    /// The point's number among every point the table recorded, so a
    /// checkpoint tells the point it found from a later one.
    pub generation: u64,
}

/// Why a `CHECKPOINT` is refused before its capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointRefusal
{
    /// The request carries no account (`INVALID_ARGUMENT`).
    NoAccount,
    /// No live process carries the badge (`INVALID_BADGE`).
    Unknown,
    /// The process is at no quiesce point (`NOT_QUIESCED`).
    NotQuiesced,
}

impl CheckpointRefusal
{
    /// The reply code of the refusal.
    #[must_use]
    pub const fn code(self) -> u64
    {
        match self
        {
            CheckpointRefusal::NoAccount => procmgr_errors::INVALID_ARGUMENT,
            CheckpointRefusal::Unknown => procmgr_errors::INVALID_BADGE,
            CheckpointRefusal::NotQuiesced => procmgr_errors::NOT_QUIESCED,
        }
    }
}

impl ProcessTable
{
    /// Record the quiesce point of the live process `badge` at
    /// `restore_sp`, with the Notification `notify` (a slot of procmgr's
    /// that the entry owns from then on).
    ///
    /// # Errors
    /// `INVALID_BADGE` when no live process carries the badge;
    /// `NOT_RESTORABLE` when it was created pinned or phys-class, or with a
    /// DMA hold; `INVALID_ARGUMENT` when it is at a point already. The
    /// caller keeps `notify` on every error.
    pub fn quiesce_enter(&mut self, badge: u64, restore_sp: u64, notify: u64) -> Result<(), u64>
    {
        let generation = self.quiesce_generation.wrapping_add(1);
        let entry = self
            .find_mut_by_badge(badge)
            .ok_or(procmgr_errors::INVALID_BADGE)?;
        match entry.quiesce
        {
            Quiesce::Refused => return Err(procmgr_errors::NOT_RESTORABLE),
            _ if entry.dma_hold => return Err(procmgr_errors::NOT_RESTORABLE),
            Quiesce::At(_) => return Err(procmgr_errors::INVALID_ARGUMENT),
            Quiesce::Idle =>
            {}
        }
        entry.quiesce = Quiesce::At(QuiescePoint {
            restore_sp,
            notify,
            generation,
        });
        self.quiesce_generation = generation;
        Ok(())
    }

    /// End the quiesce point of the live process `badge`, if it is at one,
    /// and return the slot of its Notification for the caller to delete;
    /// `0` when it was at none.
    ///
    /// # Errors
    /// `INVALID_BADGE` when no live process carries the badge.
    pub fn quiesce_end(&mut self, badge: u64) -> Result<u64, u64>
    {
        let entry = self
            .find_mut_by_badge(badge)
            .ok_or(procmgr_errors::INVALID_BADGE)?;
        Ok(entry.end_quiesce())
    }

    /// The slot of the Notification of the quiesce point numbered
    /// `generation`, while the live process `badge` is still at it: a
    /// checkpoint's check under its hold.
    ///
    /// # Errors
    /// `INVALID_BADGE` when no live process carries the badge;
    /// `NOT_QUIESCED` when it is at no point, or at a later one.
    pub fn quiesce_notify(&self, badge: u64, generation: u64) -> Result<u64, u64>
    {
        let entry = self
            .find_by_badge(badge)
            .ok_or(procmgr_errors::INVALID_BADGE)?;
        match entry.quiesce
        {
            Quiesce::At(point) if point.generation == generation => Ok(point.notify),
            Quiesce::At(_) | Quiesce::Idle | Quiesce::Refused => Err(procmgr_errors::NOT_QUIESCED),
        }
    }
}

impl ProcessEntry
{
    /// End the entry's quiesce point, if any, and return the slot of its
    /// Notification for the caller to delete; `0` with none. A process that
    /// could never quiesce stays so.
    pub fn end_quiesce(&mut self) -> u64
    {
        match self.quiesce
        {
            Quiesce::At(point) =>
            {
                self.quiesce = Quiesce::Idle;
                point.notify
            }
            Quiesce::Idle | Quiesce::Refused => 0,
        }
    }
}

/// The entry a `CHECKPOINT` for the process badge `target` reaches, and
/// the quiesce point it found, or why it is refused: the account cap
/// `account` (0 when the request carried none) first, so a request without
/// one learns nothing of the table, then the target's presence and its
/// point.
///
/// # Errors
/// The [`CheckpointRefusal`] that refuses it.
pub fn checkpoint_target(
    table: &mut ProcessTable,
    target: u64,
    account: u64,
) -> Result<(&mut ProcessEntry, QuiescePoint), CheckpointRefusal>
{
    if account == 0
    {
        return Err(CheckpointRefusal::NoAccount);
    }
    let entry = table
        .find_mut_by_badge(target)
        .ok_or(CheckpointRefusal::Unknown)?;
    match entry.quiesce
    {
        Quiesce::At(point) => Ok((entry, point)),
        Quiesce::Idle | Quiesce::Refused => Err(CheckpointRefusal::NotQuiesced),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::tests::entry_with_badge;
    use ipc::procmgr_errors::{INVALID_ARGUMENT, INVALID_BADGE, NOT_QUIESCED, NOT_RESTORABLE};

    fn table_with(entries: impl IntoIterator<Item = ProcessEntry>) -> ProcessTable
    {
        let mut table = ProcessTable::new();
        for entry in entries
        {
            table.insert(entry).unwrap();
        }
        table
    }

    fn quiescent(badge: u64) -> ProcessEntry
    {
        ProcessEntry {
            quiesce: Quiesce::Idle,
            ..entry_with_badge(badge)
        }
    }

    #[test]
    fn only_a_paged_child_outside_the_phys_class_may_quiesce()
    {
        assert_eq!(Quiesce::for_child(true, false), Quiesce::Idle);
        assert_eq!(Quiesce::for_child(false, false), Quiesce::Refused);
        assert_eq!(Quiesce::for_child(true, true), Quiesce::Refused);
    }

    #[test]
    fn a_point_is_entered_checkpointed_and_ended()
    {
        let mut table = table_with([quiescent(0x50)]);
        assert_eq!(
            checkpoint_target(&mut table, 0x50, 9).map(|(_, p)| p),
            Err(CheckpointRefusal::NotQuiesced)
        );
        table.quiesce_enter(0x50, 0x7000, 33).unwrap();
        let (_, point) = checkpoint_target(&mut table, 0x50, 9).unwrap();
        assert_eq!((point.restore_sp, point.notify), (0x7000, 33));
        assert_eq!(table.quiesce_notify(0x50, point.generation), Ok(33));
        assert_eq!(table.quiesce_end(0x50), Ok(33));
        assert_eq!(
            table.quiesce_notify(0x50, point.generation),
            Err(NOT_QUIESCED)
        );
        assert_eq!(
            table.quiesce_notify(0x99, point.generation),
            Err(INVALID_BADGE)
        );
        // Ending again finds no point and no Notification.
        assert_eq!(table.quiesce_end(0x50), Ok(0));
    }

    #[test]
    fn a_point_entered_again_is_not_the_point_a_checkpoint_found()
    {
        let mut table = table_with([quiescent(0x50)]);
        table.quiesce_enter(0x50, 0x7000, 33).unwrap();
        let (_, found) = checkpoint_target(&mut table, 0x50, 9).unwrap();
        assert_eq!(table.quiesce_end(0x50), Ok(33));
        table.quiesce_enter(0x50, 0x7000, 34).unwrap();
        assert_eq!(
            table.quiesce_notify(0x50, found.generation),
            Err(NOT_QUIESCED)
        );
    }

    #[test]
    fn quiesce_is_refused_where_no_restore_can_follow()
    {
        let refused = ProcessEntry {
            quiesce: Quiesce::Refused,
            ..entry_with_badge(0x60)
        };
        let held = ProcessEntry {
            dma_hold: true,
            ..quiescent(0x70)
        };
        let mut table = table_with([quiescent(0x50), refused, held]);
        assert_eq!(table.quiesce_enter(0x60, 0x7000, 33), Err(NOT_RESTORABLE));
        assert_eq!(table.quiesce_enter(0x70, 0x7000, 33), Err(NOT_RESTORABLE));
        assert_eq!(table.quiesce_enter(0x99, 0x7000, 33), Err(INVALID_BADGE));
        assert_eq!(table.quiesce_end(0x99), Err(INVALID_BADGE));
        table.quiesce_enter(0x50, 0x7000, 33).unwrap();
        // A second point while one is recorded keeps the first.
        assert_eq!(table.quiesce_enter(0x50, 0x6000, 34), Err(INVALID_ARGUMENT));
        assert_eq!(table.quiesce_end(0x50), Ok(33));
        // A process that can never quiesce has nothing to end.
        assert_eq!(table.quiesce_end(0x60), Ok(0));
    }

    #[test]
    fn a_checkpoint_checks_its_account_before_the_table()
    {
        let mut table = table_with([quiescent(0x50)]);
        table.quiesce_enter(0x50, 0x7000, 33).unwrap();
        assert_eq!(
            checkpoint_target(&mut table, 0x99, 0).map(|(_, p)| p),
            Err(CheckpointRefusal::NoAccount)
        );
        assert_eq!(
            checkpoint_target(&mut table, 0x99, 9).map(|(_, p)| p),
            Err(CheckpointRefusal::Unknown)
        );
        assert_eq!(CheckpointRefusal::NotQuiesced.code(), NOT_QUIESCED);
    }
}
