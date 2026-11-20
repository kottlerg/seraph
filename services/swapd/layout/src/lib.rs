// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/swapd/layout/src/lib.rs

//! swapd's decisions, host-tested: where a slot lies on the swap partition
//! ([`Geometry`]), what a held fault's reply is once a restore was tried
//! ([`fault_reply`]), what a block request's outcome means ([`transfer`]),
//! and what the write-out does after a `SWAP_TAKE` ([`after_take`])
//! (services/swapd/docs/operation.md). swapd's `main.rs` makes the calls.

#![no_std]

use free_pool::disk::{SLOT_BYTES, word_len, word_slot};
use ipc::{blk_errors, memmgr_errors};

/// The fault decline word swapd forwards a held fault with when it cannot
/// read the fault's slot: code 12, the chunk on disk, with detail 2
/// (`services/memmgr/docs/ipc-interface.md` § Kernel-origin fault message).
/// The chunk stays on disk.
pub const UNREADABLE_WORD: u64 = 0xC | (2 << 32);

/// Reads of one slot swapd makes for a restore before it forwards the fault
/// with [`UNREADABLE_WORD`]: a device's I/O error can be transient.
pub const READ_TRIES: u32 = 3;

/// `SWAP_TAKE`s that reply `NOTHING_TO_TAKE` in a row before the write-out
/// waits [`TAKE_BACKOFF_MS`]: each walks a bounded part of memmgr's records
/// from where the last stopped, so this many cover them many times over.
pub const TAKE_SWEEP: u32 = 64;

/// How long the write-out waits, or until the level changes, after a sweep
/// found nothing to take or memmgr could not take a chunk for want of memory.
pub const TAKE_BACKOFF_MS: u64 = 50;

/// How long the write-out waits, or until the level changes, once every slot
/// is taken, memmgr refused a take, or a slot was not written: a restore
/// frees a slot without a change of the level, and a device that fails a
/// write may fail the next.
pub const FULL_BACKOFF_MS: u64 = 1000;

/// The swap partition's geometry: its logical block size and its length in
/// blocks, as the block driver's `BLK_GET_GEOMETRY` reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry
{
    block: u64,
    blocks: u64,
}

/// Where one slot's bytes lie on the partition: the first block and the
/// block count, in the partition's logical blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent
{
    pub lba: u64,
    pub count: u64,
}

impl Geometry
{
    /// The geometry of a partition of `blocks` blocks of `block` bytes, or
    /// `None` when the block size is not a power of two that divides a slot.
    #[must_use]
    pub const fn new(block: u64, blocks: u64) -> Option<Self>
    {
        if block == 0 || !block.is_power_of_two() || block > SLOT_BYTES
        {
            return None;
        }
        Some(Self { block, blocks })
    }

    /// The slots the partition holds: each slot [`SLOT_BYTES`] long, at slot
    /// index times [`SLOT_BYTES`] into the partition.
    #[must_use]
    pub const fn slots(&self) -> u64
    {
        match self.blocks.checked_div(self.slot_blocks())
        {
            Some(slots) => slots,
            None => 0,
        }
    }

    /// The blocks a slot takes: at least one, the block dividing a slot.
    const fn slot_blocks(&self) -> u64
    {
        match SLOT_BYTES.checked_div(self.block)
        {
            Some(blocks) => blocks,
            None => 0,
        }
    }

    /// The extent of the first `len` bytes of slot `slot`, or `None` when
    /// the slot lies past the partition or `len` is zero or larger than a
    /// slot.
    #[must_use]
    pub fn extent(&self, slot: u32, len: u64) -> Option<Extent>
    {
        let slot = u64::from(slot);
        if slot >= self.slots() || len == 0 || len > SLOT_BYTES
        {
            return None;
        }
        Some(Extent {
            lba: slot.checked_mul(self.slot_blocks())?,
            count: len
                .checked_next_multiple_of(self.block)?
                .checked_div(self.block)?,
        })
    }

    /// The extent of the bytes a slot word names (`free_pool::disk::slot_word`):
    /// a fault's redirect word, or a word `SWAP_TAKE` or `SWAP_WANTED` replied.
    #[must_use]
    pub fn word_extent(&self, word: u64) -> Option<Extent>
    {
        self.extent(word_slot(word), u64::from(word_len(word)))
    }
}

/// How swapd answers a fault it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReply
{
    /// `FAULT_REPLY_RESUME`: the chunk is resident, or the word was stale
    /// and the thread faults again onto the chunk as it now stands.
    Resume,
    /// `FAULT_REPLY_FORWARD` with this decline word.
    Forward(u64),
}

/// The reply to a held fault once memmgr replied `label`, with word 0
/// `word`, to its `SWAP_RESTORE`. `INVALID_ARGUMENT` is swapd's own
/// malformed request, which no retry corrects: the fault is forwarded as
/// one whose slot swapd cannot read.
#[must_use]
pub const fn fault_reply(label: u64, word: u64) -> FaultReply
{
    match label
    {
        memmgr_errors::SUCCESS | memmgr_errors::RESTORE_STALE => FaultReply::Resume,
        memmgr_errors::RESTORE_DECLINED => FaultReply::Forward(word),
        _ => FaultReply::Forward(UNREADABLE_WORD),
    }
}

/// What a block request's reply label means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer
{
    /// The blocks were moved.
    Done,
    /// The device failed this request; another may succeed.
    Failed,
    /// The block driver fails every request from now on (`DEVICE_FAULT`),
    /// or is gone ([`AfterFailedCall::Lose`]): the partition is lost for
    /// this boot.
    Lost,
}

/// The meaning of a block request's reply `label`. A call that failed has
/// no reply: swapd probes the partition then ([`after_probe`]).
#[must_use]
pub const fn transfer(label: u64) -> Transfer
{
    match label
    {
        blk_errors::SUCCESS => Transfer::Done,
        blk_errors::DEVICE_FAULT => Transfer::Lost,
        _ => Transfer::Failed,
    }
}

/// What a probe of the partition showed, a call that lends no buffer
/// (`BLK_GET_GEOMETRY`) made after a block request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe
{
    /// The block driver replied: it lives.
    Replied,
    /// The partition cap is gone: the driver died and devmgr revoked its
    /// endpoint, and with it the cap vfsd keeps for the partition.
    CapGone,
    /// The probe was interrupted with the cap still live: the thread was
    /// stopped, or the driver died and devmgr has not yet revoked its
    /// endpoint, which the probe, queued on it, then waits for.
    Interrupted,
    /// The probe failed otherwise with the cap still live.
    Failed,
}

/// What swapd does after a block request failed and a probe showed a
/// [`Probe`] (services/swapd/docs/operation.md § Disk Failure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterFailedCall
{
    /// End with a fault: the driver lives, and the request's buffer may be
    /// its, so the next instance takes the partition and its buffers again.
    Restart,
    /// Mark the partition lost: no instance can take it again this boot.
    Lose,
    /// Probe again.
    ProbeAgain,
}

/// swapd's move after a block request failed and a probe showed `probe`.
#[must_use]
pub const fn after_probe(probe: Probe) -> AfterFailedCall
{
    match probe
    {
        Probe::Replied | Probe::Failed => AfterFailedCall::Restart,
        Probe::CapGone => AfterFailedCall::Lose,
        Probe::Interrupted => AfterFailedCall::ProbeAgain,
    }
}

/// How long the write-out waits, or until the level changes, after it ended
/// a write whose transfer had `outcome`: none when the slot was written,
/// [`FULL_BACKOFF_MS`] when it was not, so a device that fails every write is
/// not asked again at once.
#[must_use]
pub const fn after_write(outcome: Transfer) -> Option<u64>
{
    match outcome
    {
        Transfer::Done => None,
        Transfer::Failed | Transfer::Lost => Some(FULL_BACKOFF_MS),
    }
}

/// What the write-out does after a `SWAP_TAKE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterTake
{
    /// Write the slot's bytes and end the write with `SWAP_DONE`.
    Write,
    /// Take again at once: the walk stopped within its bound.
    Again,
    /// Wait [`TAKE_BACKOFF_MS`], or for a change of the level, and take
    /// again.
    Backoff,
    /// Every slot is taken: wait for a change of the level.
    Full,
    /// memmgr refused the request: no swap service is registered, the
    /// registration having been replaced, or the buffer is wrong.
    Refused,
}

/// The write-out's move after `SWAP_TAKE` replied `label`, the sweep having
/// found nothing `empty` times in a row before it.
#[must_use]
pub const fn after_take(label: u64, empty: u32) -> AfterTake
{
    match label
    {
        memmgr_errors::SUCCESS => AfterTake::Write,
        memmgr_errors::NOTHING_TO_TAKE if empty.saturating_add(1) < TAKE_SWEEP => AfterTake::Again,
        memmgr_errors::NOTHING_TO_TAKE | memmgr_errors::QUOTA => AfterTake::Backoff,
        memmgr_errors::SWAP_FULL => AfterTake::Full,
        _ => AfterTake::Refused,
    }
}

#[cfg(test)]
mod tests
{
    use free_pool::disk::slot_word;

    use super::*;

    #[test]
    fn a_geometry_takes_a_power_of_two_block_that_divides_a_slot()
    {
        assert!(Geometry::new(512, 1).is_some());
        assert!(Geometry::new(4096, 1).is_some());
        assert!(Geometry::new(0, 1).is_none());
        assert!(Geometry::new(1536, 1).is_none());
        assert!(Geometry::new(SLOT_BYTES * 2, 1).is_none());
    }

    #[test]
    fn slots_are_whole_slots_of_the_partition()
    {
        let g = Geometry::new(512, 64 * 1024 * 1024 / 512).unwrap();
        assert_eq!(g.slots(), 64 * 1024 * 1024 / SLOT_BYTES);
        // A partial slot at the end is not a slot.
        let g = Geometry::new(4096, SLOT_BYTES / 4096 * 3 + 5).unwrap();
        assert_eq!(g.slots(), 3);
        assert_eq!(Geometry::new(512, 0).unwrap().slots(), 0);
    }

    #[test]
    fn an_extent_lies_at_its_slot_and_covers_its_bytes_in_whole_blocks()
    {
        let g = Geometry::new(512, SLOT_BYTES / 512 * 4).unwrap();
        assert_eq!(g.extent(0, 1), Some(Extent { lba: 0, count: 1 }));
        assert_eq!(
            g.extent(2, 513),
            Some(Extent {
                lba: 2 * SLOT_BYTES / 512,
                count: 2
            })
        );
        assert_eq!(
            g.extent(3, SLOT_BYTES),
            Some(Extent {
                lba: 3 * SLOT_BYTES / 512,
                count: SLOT_BYTES / 512
            })
        );
        // The last slot's extent ends at the partition's end.
        let last = g.extent(3, SLOT_BYTES).unwrap();
        assert_eq!(last.lba + last.count, SLOT_BYTES / 512 * 4);
    }

    #[test]
    fn an_extent_past_the_partition_or_of_no_bytes_or_too_many_is_refused()
    {
        let g = Geometry::new(4096, SLOT_BYTES / 4096 * 4).unwrap();
        assert_eq!(g.extent(4, 1), None);
        assert_eq!(g.extent(u32::MAX, 1), None);
        assert_eq!(g.extent(0, 0), None);
        assert_eq!(g.extent(0, SLOT_BYTES + 1), None);
    }

    #[test]
    fn a_slot_words_extent_is_its_slots_and_byte_counts()
    {
        let g = Geometry::new(512, SLOT_BYTES / 512 * 8).unwrap();
        let word = slot_word(5, 4000, 77);
        assert_eq!(
            g.word_extent(word),
            Some(Extent {
                lba: 5 * SLOT_BYTES / 512,
                count: 8
            })
        );
        assert_eq!(g.word_extent(slot_word(8, 4000, 1)), None);
        // A raw chunk's bytes fill the slot: the word's length field holds
        // the count less one, so 65536 bytes name the whole slot.
        assert_eq!(
            g.word_extent(slot_word(5, 65536, 77)),
            Some(Extent {
                lba: 5 * SLOT_BYTES / 512,
                count: SLOT_BYTES / 512
            })
        );
    }

    #[test]
    fn a_held_fault_resumes_on_a_restore_or_a_stale_word_and_is_forwarded_otherwise()
    {
        assert_eq!(fault_reply(memmgr_errors::SUCCESS, 0), FaultReply::Resume);
        assert_eq!(
            fault_reply(memmgr_errors::RESTORE_STALE, 0),
            FaultReply::Resume
        );
        let lost = 0xC | (1 << 32);
        assert_eq!(
            fault_reply(memmgr_errors::RESTORE_DECLINED, lost),
            FaultReply::Forward(lost)
        );
        assert_eq!(
            fault_reply(memmgr_errors::INVALID_ARGUMENT, 0),
            FaultReply::Forward(UNREADABLE_WORD)
        );
    }

    #[test]
    fn only_a_device_fault_loses_the_partition()
    {
        assert_eq!(transfer(blk_errors::SUCCESS), Transfer::Done);
        assert_eq!(transfer(blk_errors::DEVICE_STATUS_IOERR), Transfer::Failed);
        assert_eq!(transfer(blk_errors::OUT_OF_BOUNDS), Transfer::Failed);
        assert_eq!(transfer(blk_errors::DEVICE_STATUS_UNSUPP), Transfer::Failed);
        assert_eq!(transfer(blk_errors::DEVICE_FAULT), Transfer::Lost);
    }

    #[test]
    fn a_failed_call_restarts_with_the_driver_alive_and_loses_it_gone()
    {
        assert_eq!(after_probe(Probe::Replied), AfterFailedCall::Restart);
        assert_eq!(after_probe(Probe::Failed), AfterFailedCall::Restart);
        assert_eq!(after_probe(Probe::CapGone), AfterFailedCall::Lose);
        assert_eq!(after_probe(Probe::Interrupted), AfterFailedCall::ProbeAgain);
    }

    #[test]
    fn a_write_not_made_backs_off()
    {
        assert_eq!(after_write(Transfer::Done), None);
        assert_eq!(after_write(Transfer::Failed), Some(FULL_BACKOFF_MS));
        assert_eq!(after_write(Transfer::Lost), Some(FULL_BACKOFF_MS));
    }

    #[test]
    fn the_write_out_sweeps_then_backs_off_and_waits_when_full()
    {
        assert_eq!(after_take(memmgr_errors::SUCCESS, 9), AfterTake::Write);
        assert_eq!(
            after_take(memmgr_errors::NOTHING_TO_TAKE, 0),
            AfterTake::Again
        );
        assert_eq!(
            after_take(memmgr_errors::NOTHING_TO_TAKE, TAKE_SWEEP - 2),
            AfterTake::Again
        );
        assert_eq!(
            after_take(memmgr_errors::NOTHING_TO_TAKE, TAKE_SWEEP - 1),
            AfterTake::Backoff
        );
        assert_eq!(after_take(memmgr_errors::QUOTA, 0), AfterTake::Backoff);
        assert_eq!(after_take(memmgr_errors::SWAP_FULL, 0), AfterTake::Full);
        assert_eq!(
            after_take(memmgr_errors::INVALID_ARGUMENT, 0),
            AfterTake::Refused
        );
    }
}
