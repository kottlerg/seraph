// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/swap/src/lib.rs

//! vfsd's hand-out of the swap partition: the decisions of
//! `vfsd_labels::GET_SWAP_PARTITION` (`services/vfsd/docs/vfs-ipc-interface.md`), apart from the
//! syscalls and IPC that carry them out.
//!
//! [`SwapPartition`] keeps the partition cap vfsd registered for the swap partition, and each
//! hand-out derives the caller's cap from it. One holder at a time reaches the partition: a
//! hand-out after the first revokes every cap derived from the kept one, then ends the regions
//! the block driver holds for the partition's badge (`blk_labels::BLK_END_REGIONS`), before it
//! derives the new one, and refuses when that revoke or that end fails. vfsd calls [`SwapPartition::hand_out`] under one
//! lock, so the first request's registration and a later request's revoke never interleave.
//!
//! The crate performs no I/O; vfsd supplies the operations through [`SwapOps`], so the hand-out
//! is host-tested (see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

use gpt::{GptLookupError, PartitionLocation};

/// The operations a hand-out runs, which vfsd carries out with IPC and capability syscalls.
pub trait SwapOps
{
    /// Look up the swap partition: the one the storage statement names, else the boot disk's
    /// by type and priority (`docs/storage.md` § GPT Role-GUID Discovery).
    ///
    /// # Errors
    /// [`GptLookupError::NotFound`] when there is none, [`GptLookupError::WrongType`] when the
    /// named partition is not a swap partition, [`GptLookupError::Elsewhere`] when it is not on
    /// the disk the statement binds it to, [`GptLookupError::DuplicateTie`] when two or more
    /// answer equally.
    fn lookup(&mut self) -> Result<PartitionLocation, GptLookupError>;

    /// Register `location` with its disk's block driver and return the partition cap the driver
    /// mints, or `None` when the registration fails.
    fn register(&mut self, location: &PartitionLocation) -> Option<u64>;

    /// Revoke every cap derived from `cap`, keeping `cap`; `false` when the revoke fails.
    fn revoke_descendants(&mut self, cap: u64) -> bool;

    /// End every region the block driver holds for `cap`'s badge (`BLK_END_REGIONS` on
    /// `cap`), so a holder the revoke cut off keeps none.
    fn end_regions(&mut self, cap: u64) -> RegionsEnd;

    /// Derive the caller's cap from `cap`, or `None` when the derivation fails.
    fn derive(&mut self, cap: u64) -> Option<u64>;
}

/// How a `BLK_END_REGIONS` sent after a revoke ended
/// (`services/drivers/virtio/blk/README.md` § Label 10: `BLK_END_REGIONS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionsEnd
{
    /// The driver ended every region of the badge.
    Ended,
    /// The block driver is gone: it took its regions with it, since devmgr revokes a dead
    /// driver's service endpoint, from which every region cap derives.
    DriverGone,
    /// Any other outcome: the cut-off holder's regions may still be live.
    Failed,
}

impl RegionsEnd
{
    /// Classify the call: `Ok(true)` for a `SUCCESS` reply, `Ok(false)` for any other reply
    /// label, `Err` the IPC call's error code. `NoReceiver` (the driver's receive right died
    /// with it) and `InvalidCapability` (devmgr's withdrawal revoked the cap the call was sent
    /// on) are the driver's death.
    #[must_use]
    pub fn of(reply: Result<bool, i64>) -> Self
    {
        use syscall_abi::SyscallError;
        match reply
        {
            Ok(true) => Self::Ended,
            Err(code)
                if code == SyscallError::NoReceiver as i64
                    || code == SyscallError::InvalidCapability as i64 =>
            {
                Self::DriverGone
            }
            Ok(false) | Err(_) => Self::Failed,
        }
    }
}

/// Why a hand-out returned no cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandOutError
{
    /// There is no swap partition: none on the boot disk and none named, the named one not
    /// found, or the named one of another type.
    NoPartition,
    /// Two or more swap partitions answer equally: a tie at the highest priority on the boot
    /// disk, or the named one found twice.
    Ambiguous,
    /// The block driver refused the registration, or the call failed.
    Register,
    /// The revoke of the previous holder's cap failed; no new cap is derived, so the previous
    /// holder stays the only one.
    Revoke,
    /// The end of the cut-off holder's regions failed for a reason other than the driver's
    /// death; no new cap is derived, and no holder reaches the partition until a later hand-out
    /// succeeds.
    EndRegions,
    /// The derivation failed. No holder reaches the partition until a later hand-out succeeds.
    Derive,
}

/// The swap partition cap vfsd keeps, registered on the first hand-out that finds the partition.
#[derive(Debug, Default)]
pub struct SwapPartition
{
    /// The registered partition cap, or `0` before a registration succeeded.
    kept: u64,
}

impl SwapPartition
{
    /// No partition registered yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { kept: 0 }
    }

    /// The kept partition cap, or `0` when none is registered.
    #[must_use]
    pub fn kept(&self) -> u64
    {
        self.kept
    }

    /// Hand out a cap on the swap partition and return it.
    ///
    /// The first hand-out looks the partition up and registers it, and keeps the cap; a failed
    /// lookup or registration keeps nothing, so a later hand-out tries again. Every later
    /// hand-out first revokes the caps derived from the kept one, cutting off the previous
    /// holder, and then ends the regions the block driver holds for the partition, so the
    /// previous holder keeps none; a driver that is gone took them with it. Then the caller's
    /// cap is derived from the kept one.
    ///
    /// # Errors
    /// The [`HandOutError`] of the step that failed.
    pub fn hand_out(&mut self, ops: &mut impl SwapOps) -> Result<u64, HandOutError>
    {
        if self.kept == 0
        {
            let location = ops.lookup().map_err(|e| match e
            {
                GptLookupError::NotFound
                | GptLookupError::WrongType
                | GptLookupError::Elsewhere { .. } => HandOutError::NoPartition,
                GptLookupError::DuplicateTie => HandOutError::Ambiguous,
            })?;
            self.kept = ops.register(&location).ok_or(HandOutError::Register)?;
        }
        else if !ops.revoke_descendants(self.kept)
        {
            return Err(HandOutError::Revoke);
        }
        else if ops.end_regions(self.kept) == RegionsEnd::Failed
        {
            return Err(HandOutError::EndRegions);
        }
        ops.derive(self.kept).ok_or(HandOutError::Derive)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const LOCATION: PartitionLocation = PartitionLocation {
        disk: 1,
        first_lba: 0x80_0000,
        length_lba: 0x2_0000,
    };

    /// A model of vfsd's operations: the partition caps the block driver minted, and the caps
    /// derived from each that are still live (each a holder that reaches the partition).
    struct Model
    {
        lookup: Result<PartitionLocation, GptLookupError>,
        register_ok: bool,
        revoke_ok: bool,
        end: RegionsEnd,
        /// Holders the driver still serves a region of: each revoke-cut holder until an end.
        regions: Vec<u64>,
        derive_ok: bool,
        registered: Vec<(PartitionLocation, u64)>,
        /// `(parent, cap)` of each live derivation.
        live: Vec<(u64, u64)>,
        next_cap: u64,
        calls: Vec<&'static str>,
    }

    impl Model
    {
        fn with_partition() -> Self
        {
            Self::with_lookup(Ok(LOCATION))
        }

        fn with_lookup(lookup: Result<PartitionLocation, GptLookupError>) -> Self
        {
            Model {
                lookup,
                register_ok: true,
                revoke_ok: true,
                end: RegionsEnd::Ended,
                regions: Vec::new(),
                derive_ok: true,
                registered: Vec::new(),
                live: Vec::new(),
                next_cap: 100,
                calls: Vec::new(),
            }
        }

        fn mint(&mut self) -> u64
        {
            self.next_cap += 1;
            self.next_cap
        }
    }

    impl SwapOps for Model
    {
        fn lookup(&mut self) -> Result<PartitionLocation, GptLookupError>
        {
            self.calls.push("lookup");
            self.lookup
        }

        fn register(&mut self, location: &PartitionLocation) -> Option<u64>
        {
            self.calls.push("register");
            if !self.register_ok
            {
                return None;
            }
            let cap = self.mint();
            self.registered.push((*location, cap));
            Some(cap)
        }

        fn revoke_descendants(&mut self, cap: u64) -> bool
        {
            self.calls.push("revoke");
            if self.revoke_ok
            {
                // A revoke cuts the holder off the partition but not off the regions it
                // registered.
                self.live.retain(|&(parent, _)| parent != cap);
            }
            self.revoke_ok
        }

        fn end_regions(&mut self, _cap: u64) -> RegionsEnd
        {
            self.calls.push("end");
            if self.end != RegionsEnd::Failed
            {
                self.regions.clear();
            }
            self.end
        }

        fn derive(&mut self, cap: u64) -> Option<u64>
        {
            self.calls.push("derive");
            if !self.derive_ok
            {
                return None;
            }
            let child = self.mint();
            self.live.push((cap, child));
            // Each holder registers a region.
            self.regions.push(child);
            Some(child)
        }
    }

    #[test]
    fn no_swap_partition_answers_no_partition_and_registers_nothing()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_lookup(Err(GptLookupError::NotFound));
        for _ in 0..2
        {
            assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::NoPartition));
        }
        assert_eq!(swap.kept(), 0);
        assert_eq!(ops.registered, Vec::new());
        assert_eq!(ops.live, Vec::new());
        assert_eq!(ops.calls, ["lookup", "lookup"]);
    }

    // Defect caught: a statement naming a partition of another type as swap, and vfsd handing
    // it to swapd.
    #[test]
    fn a_named_partition_of_another_type_answers_no_partition()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_lookup(Err(GptLookupError::WrongType));
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::NoPartition));
        // Defect caught: a named partition seen off the disk its statement
        // binds it to handed to swapd from there.
        let mut moved = Model::with_lookup(Err(GptLookupError::Elsewhere { disk: 1 }));
        assert_eq!(swap.hand_out(&mut moved), Err(HandOutError::NoPartition));
        assert_eq!(swap.kept(), 0);
        assert_eq!(swap.kept(), 0);
        assert_eq!(ops.registered, Vec::new());
    }

    #[test]
    fn a_tie_answers_ambiguous_and_registers_nothing()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_lookup(Err(GptLookupError::DuplicateTie));
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Ambiguous));
        assert_eq!(swap.kept(), 0);
        assert_eq!(ops.registered, Vec::new());
    }

    #[test]
    fn the_first_hand_out_registers_the_partition_once_and_derives_from_it()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.registered.len(), 1);
        let (location, kept) = ops.registered[0];
        assert_eq!(location, LOCATION);
        assert_eq!(swap.kept(), kept);
        assert_eq!(ops.live, [(kept, cap)]);
        assert_eq!(ops.calls, ["lookup", "register", "derive"]);
    }

    #[test]
    fn a_second_hand_out_revokes_the_first_holder_before_it_derives()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let first = swap.hand_out(&mut ops).unwrap();
        let second = swap.hand_out(&mut ops).unwrap();
        assert_ne!(first, second);
        // One registration, and only the second cap reaches the partition.
        assert_eq!(ops.registered.len(), 1);
        assert_eq!(ops.live, [(swap.kept(), second)]);
        assert_eq!(
            ops.calls,
            ["lookup", "register", "derive", "revoke", "end", "derive"]
        );
        // Defect caught: a revoked holder keeping the block regions it registered.
        assert_eq!(ops.regions, [second]);
    }

    // Defect caught: vfsd handing the swap partition to a new holder while the previous one
    // still reaches it through its regions.
    #[test]
    fn a_failed_end_derives_nothing_and_a_gone_driver_counts_as_ended()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let first = swap.hand_out(&mut ops).unwrap();
        ops.end = RegionsEnd::Failed;
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::EndRegions));
        assert_eq!(ops.live, Vec::new());
        assert_eq!(ops.regions, [first]);
        assert_eq!(ops.calls.last(), Some(&"end"));
        ops.end = RegionsEnd::DriverGone;
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.live, [(swap.kept(), cap)]);
    }

    #[test]
    fn an_end_reply_classifies_the_drivers_death_apart_from_other_failures()
    {
        use syscall_abi::SyscallError;
        assert_eq!(RegionsEnd::of(Ok(true)), RegionsEnd::Ended);
        assert_eq!(RegionsEnd::of(Ok(false)), RegionsEnd::Failed);
        assert_eq!(
            RegionsEnd::of(Err(SyscallError::NoReceiver as i64)),
            RegionsEnd::DriverGone
        );
        assert_eq!(
            RegionsEnd::of(Err(SyscallError::InvalidCapability as i64)),
            RegionsEnd::DriverGone
        );
        assert_eq!(
            RegionsEnd::of(Err(SyscallError::Interrupted as i64)),
            RegionsEnd::Failed
        );
    }

    #[test]
    fn a_failed_derive_after_the_revoke_leaves_no_holder_and_a_later_hand_out_recovers()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        swap.hand_out(&mut ops).unwrap();
        ops.derive_ok = false;
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Derive));
        assert_eq!(ops.live, Vec::new());
        ops.derive_ok = true;
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.live, [(swap.kept(), cap)]);
        assert_eq!(ops.registered.len(), 1);
    }

    #[test]
    fn a_failed_revoke_derives_nothing_so_the_previous_holder_stays_the_only_one()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let first = swap.hand_out(&mut ops).unwrap();
        ops.revoke_ok = false;
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Revoke));
        assert_eq!(ops.live, [(swap.kept(), first)]);
        assert_eq!(ops.calls.last(), Some(&"revoke"));
    }

    #[test]
    fn a_failed_registration_keeps_nothing_and_a_later_hand_out_registers_again()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        ops.register_ok = false;
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Register));
        assert_eq!(swap.kept(), 0);
        assert_eq!(ops.live, Vec::new());
        ops.register_ok = true;
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.registered.len(), 1);
        assert_eq!(ops.live, [(swap.kept(), cap)]);
        assert_eq!(
            ops.calls,
            ["lookup", "register", "lookup", "register", "derive"]
        );
    }
}
