// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/swap/src/lib.rs

//! vfsd's hand-out of the swap partition: the decisions of
//! `vfsd_labels::GET_SWAP_PARTITION` (`services/vfsd/docs/vfs-ipc-interface.md`), apart from the
//! syscalls and IPC that carry them out.
//!
//! [`SwapPartition`] keeps the partition cap of the current grant of the swap partition, and
//! each hand-out derives the caller's cap from a grant of its own. One holder at a time reaches
//! the partition: a hand-out cuts the previous grant off (`grant::cut_off`: revoke, retire,
//! delete), refusing when that fails, then looks the partition up, registers it under a new
//! badge, and derives the caller's cap from that grant. vfsd calls
//! [`SwapPartition::hand_out`] under one lock, so two hand-outs never interleave.
//!
//! The crate performs no I/O; vfsd supplies the operations through [`SwapOps`], so the hand-out
//! is host-tested (see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

use gpt::{GptLookupError, PartitionLocation};
use grant::GrantOps;

/// The operations a hand-out runs, which vfsd carries out with IPC and capability syscalls:
/// those of a cut-off ([`GrantOps`]), and these.
pub trait SwapOps: GrantOps
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

    /// Derive the caller's cap from `cap`, or `None` when the derivation fails.
    fn derive(&mut self, cap: u64) -> Option<u64>;
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
    /// The cut-off of the previous grant failed (`grant::CutOffFailed`): no new grant is
    /// made, so the previous holder stays the only one, and a later hand-out tries the cut-off
    /// again.
    CutOff,
    /// The block driver refused the registration, or the call failed. No holder reaches the
    /// partition until a later hand-out succeeds.
    Register,
    /// The derivation failed. No holder reaches the partition until a later hand-out succeeds.
    Derive,
}

/// The partition cap of the swap partition's current grant.
#[derive(Debug, Default)]
pub struct SwapPartition
{
    /// The partition cap of the current grant, or `0` when none is registered.
    kept: u64,
}

impl SwapPartition
{
    /// No grant made yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { kept: 0 }
    }

    /// The partition cap of the current grant, or `0` when none is registered.
    #[must_use]
    pub fn kept(&self) -> u64
    {
        self.kept
    }

    /// Hand out a cap on the swap partition and return it.
    ///
    /// A hand-out with a grant registered first cuts it off (`grant::cut_off`), ending the
    /// previous holder's reach, its block regions included; a block driver that is gone took
    /// them with it. Then it looks the partition up, so a disk served since the last hand-out
    /// is seen, registers it as a new grant, which the hand-out keeps, and derives the caller's
    /// cap from it. A step that fails keeps nothing but the grant that stays to be cut off.
    ///
    /// # Errors
    /// The [`HandOutError`] of the step that failed.
    pub fn hand_out(&mut self, ops: &mut impl SwapOps) -> Result<u64, HandOutError>
    {
        if self.kept != 0
        {
            grant::cut_off(ops, self.kept).map_err(|grant::CutOffFailed| HandOutError::CutOff)?;
            self.kept = 0;
        }
        let location = ops.lookup().map_err(|e| match e
        {
            GptLookupError::NotFound
            | GptLookupError::WrongType
            | GptLookupError::Elsewhere { .. } => HandOutError::NoPartition,
            GptLookupError::DuplicateTie => HandOutError::Ambiguous,
        })?;
        self.kept = ops.register(&location).ok_or(HandOutError::Register)?;
        ops.derive(self.kept).ok_or(HandOutError::Derive)
    }
}

#[cfg(test)]
mod tests
{
    use grant::Step;

    use super::*;

    const LOCATION: PartitionLocation = PartitionLocation {
        disk: 1,
        first_lba: 0x80_0000,
        length_lba: 0x2_0000,
    };

    /// A model of vfsd's operations on one block driver: the grants it holds, the caps derived
    /// from each kept cap, and the region each holder registered through its grant.
    struct Model
    {
        lookup: Result<PartitionLocation, GptLookupError>,
        /// The steps that fail: `"register"`, `"retire"`, `"derive"`.
        fails: Vec<&'static str>,
        /// The driver is dead: devmgr revoked its endpoint and everything derived from it.
        dead: bool,
        /// Die right before the step this many steps on.
        die_before: Option<usize>,
        /// Live grants: `(location, kept cap)`.
        grants: Vec<(PartitionLocation, u64)>,
        /// `(kept, holder)` of each live derivation.
        live: Vec<(u64, u64)>,
        /// `(kept, holder)` of each live region.
        regions: Vec<(u64, u64)>,
        /// Kept caps vfsd holds.
        held: Vec<u64>,
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
                fails: Vec::new(),
                dead: false,
                die_before: None,
                grants: Vec::new(),
                live: Vec::new(),
                regions: Vec::new(),
                held: Vec::new(),
                next_cap: 100,
                calls: Vec::new(),
            }
        }

        fn mint(&mut self) -> u64
        {
            self.next_cap += 1;
            self.next_cap
        }

        fn step(&mut self, name: &'static str)
        {
            self.calls.push(name);
            match self.die_before
            {
                Some(0) =>
                {
                    self.die_before = None;
                    self.dead = true;
                    self.grants.clear();
                    self.live.clear();
                    self.regions.clear();
                }
                Some(n) => self.die_before = Some(n - 1),
                None =>
                {}
            }
        }

        /// The driver's side of `BLK_RETIRE_PARTITION` on `cap`, sent by vfsd or by the holder
        /// of a derivation, which carries the same badge.
        fn serve_retire(&mut self, cap: u64) -> u64
        {
            if !self.grants.iter().any(|&(_, g)| g == cap)
            {
                return ipc::blk_errors::OUT_OF_BOUNDS;
            }
            self.grants.retain(|&(_, g)| g != cap);
            self.regions.retain(|&(k, _)| k != cap);
            ipc::blk_errors::SUCCESS
        }

        /// The holders that reach the partition: through a derivation of a live grant, or
        /// through a region.
        fn reaching(&self) -> Vec<u64>
        {
            let mut out: Vec<u64> = self
                .live
                .iter()
                .filter(|(k, _)| self.grants.iter().any(|(_, g)| g == k))
                .chain(self.regions.iter())
                .map(|&(_, h)| h)
                .collect();
            out.sort_unstable();
            out.dedup();
            out
        }
    }

    impl GrantOps for Model
    {
        fn revoke_descendants(&mut self, cap: u64) -> Step
        {
            self.step("revoke");
            if self.dead
            {
                return Step::DriverGone;
            }
            // A revoke cuts the holder's derivation, not the region it registered.
            self.live.retain(|&(parent, _)| parent != cap);
            Step::Done
        }

        fn retire(&mut self, cap: u64) -> Step
        {
            self.step("retire");
            if self.dead
            {
                return Step::DriverGone;
            }
            if self.fails.contains(&"retire")
            {
                return Step::of_retire(Ok(ipc::blk_errors::LABEL_VERSION_MISMATCH));
            }
            Step::of_retire(Ok(self.serve_retire(cap)))
        }

        fn delete(&mut self, cap: u64)
        {
            self.step("delete");
            self.held.retain(|&h| h != cap);
        }
    }

    impl SwapOps for Model
    {
        fn lookup(&mut self) -> Result<PartitionLocation, GptLookupError>
        {
            self.step("lookup");
            self.lookup
        }

        fn register(&mut self, location: &PartitionLocation) -> Option<u64>
        {
            self.step("register");
            if self.fails.contains(&"register") || self.dead
            {
                return None;
            }
            let cap = self.mint();
            self.grants.push((*location, cap));
            self.held.push(cap);
            Some(cap)
        }

        fn derive(&mut self, cap: u64) -> Option<u64>
        {
            self.step("derive");
            if self.fails.contains(&"derive") || self.dead
            {
                return None;
            }
            let child = self.mint();
            self.live.push((cap, child));
            // Each holder registers a region.
            self.regions.push((cap, child));
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
        assert_eq!(ops.grants, Vec::new());
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
        assert_eq!(ops.grants, Vec::new());
    }

    #[test]
    fn a_tie_answers_ambiguous_and_registers_nothing()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_lookup(Err(GptLookupError::DuplicateTie));
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Ambiguous));
        assert_eq!(swap.kept(), 0);
        assert_eq!(ops.grants, Vec::new());
    }

    #[test]
    fn the_first_hand_out_registers_the_partition_and_derives_from_it()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.grants, [(LOCATION, swap.kept())]);
        assert_eq!(ops.live, [(swap.kept(), cap)]);
        assert_eq!(ops.calls, ["lookup", "register", "derive"]);
    }

    // Defect caught: a revoked holder keeping the block regions it registered, or the next
    // holder's grant sharing the previous one's badge.
    #[test]
    fn a_second_hand_out_cuts_the_first_grant_off_and_grants_anew()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let first = swap.hand_out(&mut ops).unwrap();
        let first_kept = swap.kept();
        let second = swap.hand_out(&mut ops).unwrap();
        assert_ne!(first, second);
        assert_ne!(swap.kept(), first_kept);
        assert_eq!(ops.grants, [(LOCATION, swap.kept())]);
        assert_eq!(ops.held, [swap.kept()]);
        assert_eq!(ops.reaching(), [second]);
        assert_eq!(
            ops.calls,
            [
                "lookup", "register", "derive", "revoke", "retire", "delete", "lookup", "register",
                "derive"
            ]
        );
    }

    // Defect caught: vfsd handing the swap partition to a new holder while the previous one
    // still reaches it through its regions.
    #[test]
    fn a_failed_retire_grants_nothing_and_a_later_hand_out_completes_it()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        let first = swap.hand_out(&mut ops).unwrap();
        let kept = swap.kept();
        ops.fails.push("retire");
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::CutOff));
        assert_eq!(swap.kept(), kept);
        assert_eq!(ops.reaching(), [first]);
        assert_eq!(ops.calls.last(), Some(&"retire"));
        ops.fails.clear();
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.reaching(), [cap]);
        assert_eq!(ops.held, [swap.kept()]);
    }

    // Defect caught: the block driver's death during a hand-out refusing every later one, or
    // leaving a holder reaching the partition.
    #[test]
    fn a_driver_death_at_each_step_of_a_hand_out_leaves_no_holder_but_the_new_one()
    {
        // The steps of a second hand-out: revoke, retire, delete, lookup, register, derive.
        for die_at in 0..6
        {
            let mut swap = SwapPartition::new();
            let mut ops = Model::with_partition();
            swap.hand_out(&mut ops).unwrap();
            ops.die_before = Some(die_at);
            let got = swap.hand_out(&mut ops);
            assert!(
                matches!(got, Err(HandOutError::Register | HandOutError::Derive)),
                "death before step {die_at}: {got:?}"
            );
            assert_eq!(
                ops.reaching(),
                Vec::<u64>::new(),
                "death before step {die_at}"
            );
            // A dead driver's grant cuts off as gone, so the next hand-out is refused only
            // at its registration, never at the cut-off.
            assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Register));
            assert_eq!(swap.kept(), 0);
        }
    }

    #[test]
    fn a_failed_derive_leaves_no_holder_and_a_later_hand_out_recovers()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        swap.hand_out(&mut ops).unwrap();
        ops.fails.push("derive");
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Derive));
        assert_eq!(ops.reaching(), Vec::<u64>::new());
        ops.fails.clear();
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.reaching(), [cap]);
        assert_eq!(ops.grants.len(), 1);
        assert_eq!(ops.held, [swap.kept()]);
    }

    #[test]
    fn a_failed_registration_keeps_nothing_and_a_later_hand_out_registers_again()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        ops.fails.push("register");
        assert_eq!(swap.hand_out(&mut ops), Err(HandOutError::Register));
        assert_eq!(swap.kept(), 0);
        ops.fails.clear();
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.grants.len(), 1);
        assert_eq!(ops.live, [(swap.kept(), cap)]);
        assert_eq!(
            ops.calls,
            ["lookup", "register", "lookup", "register", "derive"]
        );
    }

    // Defect caught: a partition found once granted from there for good, so a swap partition
    // whose disk came back under another index is never handed out again.
    #[test]
    fn each_hand_out_looks_the_partition_up_again()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        swap.hand_out(&mut ops).unwrap();
        let moved = PartitionLocation {
            disk: 2,
            ..LOCATION
        };
        ops.lookup = Ok(moved);
        swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.grants, [(moved, swap.kept())]);
    }

    // Defect caught: a grant its holder retired refusing every later hand-out as a failed
    // cut-off, so a restarted swap service gets no swap partition.
    #[test]
    fn a_grant_its_holder_retired_does_not_block_the_next_hand_out()
    {
        let mut swap = SwapPartition::new();
        let mut ops = Model::with_partition();
        swap.hand_out(&mut ops).unwrap();
        let kept = swap.kept();
        assert_eq!(ops.serve_retire(kept), ipc::blk_errors::SUCCESS);
        let cap = swap.hand_out(&mut ops).unwrap();
        assert_eq!(ops.reaching(), [cap]);
        assert_eq!(ops.held, [swap.kept()]);
    }
}
