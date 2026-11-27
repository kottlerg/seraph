// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/grant/src/lib.rs

//! vfsd's grants of a block partition: the sequence that cuts a holder off a partition, apart
//! from the syscalls and IPC that carry it out
//! (`services/vfsd/docs/namespace-composition.md` § Revocation).
//!
//! vfsd registers a partition with its disk's block driver (`blk_labels::REGISTER_PARTITION`),
//! keeps the partition cap the driver mints, and hands one holder a derivation of it. The
//! driver's badge on that cap is one grant (`services/drivers/virtio/blk/README.md` § Grants
//! and regions). [`cut_off`] ends it in the order the driver's model needs: revoke the
//! derivations, retire the badge (`blk_labels::BLK_RETIRE_PARTITION`), which ends every block
//! region registered through it and refuses every later request carrying it, then delete the
//! kept cap. A partition granted again is registered again, under a new badge. The block
//! driver's death at any step ends the grant with it: devmgr revokes a dead driver's service
//! endpoint, from which the kept cap and every region cap derive.
//!
//! The crate performs no I/O; vfsd supplies the operations through [`GrantOps`], so the
//! sequence is host-tested (see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

/// How one step on a partition cap ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step
{
    /// The step was carried out.
    Done,
    /// The block driver is gone: devmgr's withdrawal revoked its service endpoint, the kept cap
    /// and every cap the grant reached with it, its regions ended.
    DriverGone,
    /// Any other outcome: the grant may still reach the partition.
    Failed,
}

impl Step
{
    /// Classify a call on the kept cap: `Ok(true)` for its success, `Ok(false)` for any other
    /// reply, `Err` the syscall's or the IPC call's error code. `NoReceiver` (the driver's
    /// receive right died with it) and `InvalidCapability` (devmgr's withdrawal revoked the cap
    /// the call was made on) are the driver's death.
    #[must_use]
    pub fn of(outcome: Result<bool, i64>) -> Self
    {
        use syscall_abi::SyscallError;
        match outcome
        {
            Ok(true) => Self::Done,
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

/// The operations a cut-off runs on a kept partition cap, which vfsd carries out with
/// capability syscalls and IPC to the block driver.
pub trait GrantOps
{
    /// Revoke every cap derived from `cap`, keeping `cap` (`cap_revoke_all`).
    fn revoke_descendants(&mut self, cap: u64) -> Step;

    /// Retire the grant `cap` carries (`BLK_RETIRE_PARTITION` on `cap`).
    fn retire(&mut self, cap: u64) -> Step;

    /// Delete `cap` from vfsd's `CSpace`.
    fn delete(&mut self, cap: u64);
}

/// A cut-off whose retire failed for a reason other than the block driver's death: the grant
/// may still reach the partition, through a derivation the revoke missed or a block region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutOffFailed;

/// End the grant `cap` carries: revoke its derivations, retire its badge, delete `cap`.
///
/// The retire is what ends the grant: once the driver has retired the badge it serves no
/// request carrying it, so a derivation a failed revoke left reaches nothing, and the retire
/// runs whatever the revoke's outcome. The block driver's death at either step ends the grant
/// too, and the retire is not sent to a driver the revoke found gone.
///
/// # Errors
/// [`CutOffFailed`] when the retire failed for another reason; `cap` is kept, so the cut-off
/// can be tried again.
pub fn cut_off(ops: &mut impl GrantOps, cap: u64) -> Result<(), CutOffFailed>
{
    if ops.revoke_descendants(cap) != Step::DriverGone && ops.retire(cap) == Step::Failed
    {
        return Err(CutOffFailed);
    }
    ops.delete(cap);
    Ok(())
}

/// [`cut_off`] where nothing tries it again (an unmount, a failed mount, an abandoned restart):
/// `cap` is deleted whatever the outcome.
///
/// # Errors
/// [`CutOffFailed`], after the delete: the grant may still reach the partition.
pub fn release(ops: &mut impl GrantOps, cap: u64) -> Result<(), CutOffFailed>
{
    let cut = cut_off(ops, cap);
    if cut.is_err()
    {
        ops.delete(cap);
    }
    cut
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A model of one block driver and vfsd's caps on it: the grants the driver holds, the
    /// derivations of each kept cap, and the regions each grant's holder registered.
    #[derive(Default)]
    struct Driver
    {
        /// The driver is dead: devmgr revoked its endpoint and everything derived from it.
        dead: bool,
        /// Live grants, by kept cap.
        grants: Vec<u64>,
        /// `(kept, child)` of each live derivation.
        derived: Vec<(u64, u64)>,
        /// `(kept, region)` of each live region.
        regions: Vec<(u64, u64)>,
        /// Kept caps vfsd still holds.
        held: Vec<u64>,
        fail_revoke: bool,
        fail_retire: bool,
        /// Die right before the step this many steps on (`Some(0)`: the next one).
        die_before: Option<usize>,
        calls: Vec<&'static str>,
        next: u64,
    }

    impl Driver
    {
        fn register(&mut self) -> Option<u64>
        {
            self.step("register");
            if self.dead
            {
                return None;
            }
            self.next += 1;
            let cap = self.next;
            self.grants.push(cap);
            self.held.push(cap);
            Some(cap)
        }

        /// Hand a holder a derivation of `kept`, which registers a region through it.
        fn derive(&mut self, kept: u64) -> Option<u64>
        {
            self.step("derive");
            if self.dead || !self.grants.contains(&kept)
            {
                return None;
            }
            self.next += 1;
            let child = self.next;
            self.derived.push((kept, child));
            self.regions.push((kept, child));
            Some(child)
        }

        /// Whether any holder still reaches the partition through `kept`'s grant.
        fn reached(&self, kept: u64) -> bool
        {
            !self.dead
                && ((self.grants.contains(&kept) && self.derived.iter().any(|&(k, _)| k == kept))
                    || self.regions.iter().any(|&(k, _)| k == kept))
        }

        fn step(&mut self, name: &'static str)
        {
            self.calls.push(name);
            match self.die_before
            {
                Some(0) =>
                {
                    self.die_before = None;
                    self.die();
                }
                Some(n) => self.die_before = Some(n - 1),
                None =>
                {}
            }
        }

        fn die(&mut self)
        {
            self.dead = true;
            self.grants.clear();
            self.derived.clear();
            self.regions.clear();
        }
    }

    impl GrantOps for Driver
    {
        fn revoke_descendants(&mut self, cap: u64) -> Step
        {
            self.step("revoke");
            if self.dead
            {
                return Step::DriverGone;
            }
            if self.fail_revoke
            {
                return Step::Failed;
            }
            // The revoke reaches the derivations, not the regions minted from the driver's
            // endpoint.
            self.derived.retain(|&(k, _)| k != cap);
            Step::Done
        }

        fn retire(&mut self, cap: u64) -> Step
        {
            self.step("retire");
            if self.dead
            {
                return Step::DriverGone;
            }
            if self.fail_retire || !self.grants.contains(&cap)
            {
                return Step::Failed;
            }
            self.grants.retain(|&g| g != cap);
            self.regions.retain(|&(k, _)| k != cap);
            Step::Done
        }

        fn delete(&mut self, cap: u64)
        {
            self.calls.push("delete");
            self.held.retain(|&h| h != cap);
        }
    }

    // Defect caught: a cut-off holder keeping a region, or a derivation, of the grant vfsd ended.
    #[test]
    fn a_cut_off_revokes_retires_and_deletes_in_that_order()
    {
        let mut d = Driver::default();
        let kept = d.register().unwrap();
        d.derive(kept).unwrap();
        assert!(d.reached(kept));
        assert_eq!(cut_off(&mut d, kept), Ok(()));
        assert!(!d.reached(kept));
        assert_eq!(d.grants, Vec::<u64>::new());
        assert_eq!(d.held, Vec::<u64>::new());
        assert_eq!(
            d.calls,
            ["register", "derive", "revoke", "retire", "delete"]
        );
    }

    // Defect caught: a driver death mid-sequence reported as a failure (a restart or a swap
    // hand-out refused for good), or a step after it treated as live.
    #[test]
    fn a_driver_death_before_any_step_ends_the_grant()
    {
        for die_at in 0..3
        {
            let mut d = Driver::default();
            let kept = d.register().unwrap();
            d.derive(kept).unwrap();
            d.die_before = Some(die_at);
            assert_eq!(cut_off(&mut d, kept), Ok(()), "death before step {die_at}");
            assert!(!d.reached(kept));
            assert_eq!(d.held, Vec::<u64>::new());
        }
    }

    // Defect caught: a holder a failed revoke missed still reaching the partition, the retire
    // having been skipped.
    #[test]
    fn a_failed_revoke_still_retires_and_the_missed_derivation_reaches_nothing()
    {
        let mut d = Driver::default();
        let kept = d.register().unwrap();
        d.derive(kept).unwrap();
        d.fail_revoke = true;
        assert_eq!(cut_off(&mut d, kept), Ok(()));
        assert_eq!(d.derived.len(), 1, "the revoke missed the derivation");
        assert!(!d.reached(kept));
        assert_eq!(d.held, Vec::<u64>::new());
    }

    // Defect caught: the kept cap deleted after a failed retire, leaving nothing to retry the
    // cut-off with while the holder still reaches the partition.
    #[test]
    fn a_failed_retire_keeps_the_cap_and_a_retry_completes()
    {
        let mut d = Driver::default();
        let kept = d.register().unwrap();
        d.derive(kept).unwrap();
        d.fail_retire = true;
        assert_eq!(cut_off(&mut d, kept), Err(CutOffFailed));
        assert!(d.reached(kept), "the region is live until the retire");
        assert_eq!(d.held, [kept]);
        d.fail_retire = false;
        assert_eq!(cut_off(&mut d, kept), Ok(()));
        assert!(!d.reached(kept));
        assert_eq!(d.held, Vec::<u64>::new());
    }

    #[test]
    fn a_release_deletes_the_cap_whatever_the_outcome()
    {
        let mut d = Driver::default();
        let kept = d.register().unwrap();
        d.fail_retire = true;
        assert_eq!(release(&mut d, kept), Err(CutOffFailed));
        assert_eq!(d.held, Vec::<u64>::new());
        let other = d.register().unwrap();
        d.fail_retire = false;
        assert_eq!(release(&mut d, other), Ok(()));
        assert_eq!(d.held, Vec::<u64>::new());
        assert_eq!(d.grants, [kept]);
    }

    // Defect caught: a second grant of the range sharing the first's badge, so the first
    // holder's late requests reach the second grant.
    #[test]
    fn a_grant_again_is_a_new_registration_the_old_holder_does_not_reach()
    {
        let mut d = Driver::default();
        let first = d.register().unwrap();
        d.derive(first).unwrap();
        cut_off(&mut d, first).unwrap();
        let second = d.register().unwrap();
        assert_ne!(first, second);
        d.derive(second).unwrap();
        assert!(!d.reached(first));
        assert!(d.reached(second));
    }

    #[test]
    fn a_step_reply_classifies_the_drivers_death_apart_from_other_failures()
    {
        use syscall_abi::SyscallError;
        assert_eq!(Step::of(Ok(true)), Step::Done);
        assert_eq!(Step::of(Ok(false)), Step::Failed);
        assert_eq!(
            Step::of(Err(SyscallError::NoReceiver as i64)),
            Step::DriverGone
        );
        assert_eq!(
            Step::of(Err(SyscallError::InvalidCapability as i64)),
            Step::DriverGone
        );
        assert_eq!(
            Step::of(Err(SyscallError::Interrupted as i64)),
            Step::Failed
        );
    }
}
