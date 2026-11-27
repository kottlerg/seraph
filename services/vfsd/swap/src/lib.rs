// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/swap/src/lib.rs

//! vfsd's hand-out of the swap partition: the decisions of
//! `vfsd_labels::GET_SWAP_PARTITION` (`services/vfsd/docs/vfs-ipc-interface.md`), apart from the
//! syscalls and IPC that carry them out.
//!
//! [`SwapPartition`] keeps the partition cap of the current grant of the swap partition, and
//! each hand-out derives the caller's cap from a new grant. One holder at a time reaches the
//! partition: a hand-out after the first cuts the previous grant off (`grant::cut_off`:
//! revoke, retire, delete), then registers the partition again, under a new badge, and derives
//! the caller's cap from it; it refuses when the cut-off fails. vfsd calls
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

/// The swap partition vfsd found, and the partition cap of its current grant.
#[derive(Debug, Default)]
pub struct SwapPartition
{
    /// The partition the first successful lookup found; later hand-outs grant it again.
    location: Option<PartitionLocation>,
    /// The partition cap of the current grant, or `0` when none is registered.
    kept: u64,
}

impl SwapPartition
{
    /// No partition found yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            location: None,
            kept: 0,
        }
    }

    /// The partition cap of the current grant, or `0` when none is registered.
    #[must_use]
    pub fn kept(&self) -> u64
    {
        self.kept
    }

    /// Hand out a cap on the swap partition and return it.
    ///
    /// The first hand-out looks the partition up; a failed lookup keeps nothing, so a later
    /// hand-out looks again. A hand-out with a grant registered first cuts it off
    /// (`grant::cut_off`), ending the previous holder's reach, its block regions included; a
    /// block driver that is gone took them with it. Then the partition is registered as a new
    /// grant, which the hand-out keeps, and the caller's cap is derived from it.
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
        let location = if let Some(location) = self.location
        {
            location
        }
        else
        {
            let location = ops.lookup().map_err(|e| match e
            {
                GptLookupError::NotFound
                | GptLookupError::WrongType
                | GptLookupError::Elsewhere { .. } => HandOutError::NoPartition,
                GptLookupError::DuplicateTie => HandOutError::Ambiguous,
            })?;
            self.location = Some(location);
            location
        };
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
                return Step::Failed;
            }
            self.grants.retain(|&(_, g)| g != cap);
            self.regions.retain(|&(k, _)| k != cap);
            Step::Done
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
                "lookup", "register", "derive", "revoke", "retire", "delete", "register", "derive"
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
        // The steps of a second hand-out: revoke, retire, delete, register, derive.
        for die_at in 0..5
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
        // The partition is looked up once.
        assert_eq!(ops.calls, ["lookup", "register", "register", "derive"]);
    }
}
