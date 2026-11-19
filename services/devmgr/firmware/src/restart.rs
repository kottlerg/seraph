// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/restart.rs

//! devmgr's restart policy for a served driver that dies: whether devmgr
//! starts the same driver again on the same device record, from its installed
//! path, and the consumer's refusal of that restart
//! (`devmgr_labels::DECLINE_RESTART`). The policy is specified in
//! services/devmgr/docs/responsibilities.md § Driver Restart.
//!
//! A restart is decided in two steps. When devmgr takes the death, before it
//! withdraws the driver, [`restart_entry`] reads what the death and the
//! registry say: the death's reason, the consumer's refusal, and the drivers
//! directory and the driver's place in it. Once the withdrawal is done,
//! [`after_withdrawal`] reads what it left ([`Teardown`]): whether the device
//! was confirmed quiet and the driver's DMA hold released, and then the
//! record's restart budget, which only a restart that passes every other
//! check is charged.

use core::fmt;

use driver_binding::decl::{DriverDecl, DriverName, Interrupt};
use syscall_abi::EXIT_FAULT_BASE;

use crate::binding::{RecordKeys, Source, decl_rank};
use crate::served::{Lookup, Served};

/// A device record: a PCI record or a platform record, by its index in its
/// list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordId
{
    /// The PCI record at this index.
    Pci(usize),
    /// The platform record at this index.
    Platform(usize),
}

/// Why a dead driver is not restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// It exited with a code of its own: it decided to stop serving.
    Exited,
    /// Its consumer declined its restart (`DECLINE_RESTART`).
    Declined,
    /// No drivers directory is installed yet (`SET_DRIVERS_DIR`).
    NoDriversDir,
    /// Its install path is no entry of the drivers directory: it was started
    /// from another directory (`BIND_DRIVERS`).
    NotInstalled,
    /// Its device was not confirmed quiet: it may still perform DMA.
    NotQuiet,
    /// Its DMA hold stays.
    HoldKept,
    /// Its record's restart budget for the window is spent.
    BudgetSpent,
    /// devmgr has no memory to queue its restart.
    NoMemory,
}

impl fmt::Display for Refusal
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(match self
        {
            Self::Exited => "it exited",
            Self::Declined => "its consumer declined its restart",
            Self::NoDriversDir => "no drivers directory is installed",
            Self::NotInstalled => "it was not started from the drivers directory",
            Self::NotQuiet => "its device was not confirmed quiet",
            Self::HoldKept => "its DMA hold stays",
            Self::BudgetSpent => "its device's restart budget for this window is spent",
            Self::NoMemory => "no memory to queue its restart",
        })
    }
}

/// The entry of the drivers directory at `dir` that `path` names: `path` is
/// `dir`, `/`, and a non-empty entry name with no `/`. `None` otherwise.
#[must_use]
pub fn entry<'a>(dir: &[u8], path: &'a [u8]) -> Option<&'a [u8]>
{
    let name = path.strip_prefix(dir)?.strip_prefix(b"/")?;
    (!name.is_empty() && !name.contains(&b'/')).then_some(name)
}

/// When devmgr takes the death of a served driver installed at `path`, with
/// exit reason `reason`: the drivers-directory entry it restarts from, or
/// why it does not restart. `declined` is whether its consumer declined its
/// restart; `drivers_dir` is the drivers directory's path, `None` before
/// `SET_DRIVERS_DIR`.
///
/// # Errors
/// The [`Refusal`], checked in this order: an exit of its own (a reason
/// below `EXIT_FAULT_BASE`; a fault or a kill restarts), the consumer's
/// refusal, no drivers directory, a path outside it.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`declined` is data: the mark `DECLINE_RESTART` left on the dead driver"
)]
pub fn restart_entry<'a>(
    reason: u64,
    declined: bool,
    drivers_dir: Option<&[u8]>,
    path: &'a [u8],
) -> Result<&'a [u8], Refusal>
{
    if reason < EXIT_FAULT_BASE
    {
        return Err(Refusal::Exited);
    }
    if declined
    {
        return Err(Refusal::Declined);
    }
    let dir = drivers_dir.ok_or(Refusal::NoDriversDir)?;
    entry(dir, path).ok_or(Refusal::NotInstalled)
}

/// What a driver's withdrawal left of its device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Teardown
{
    /// The device was confirmed quiet: it performs no DMA. A platform device
    /// has no DMA and is quiet once its caps are taken.
    pub quiet: bool,
    /// The driver's DMA hold was released, or it held none.
    pub released: bool,
}

/// Once the withdrawal of a driver [`restart_entry`] admitted is done:
/// whether it restarts, from what the withdrawal left, `teardown`. A device
/// is handed to a new instance only when it was confirmed quiet, an IOMMU's
/// block alone not sufficing, since the new instance's bind enables its bus
/// mastering again; and only once the dead driver's DMA hold is released.
/// `charge` charges one restart to its record's budget and returns whether
/// the budget had room, and is called only when every other check passes.
///
/// # Errors
/// [`Refusal::NotQuiet`], [`Refusal::HoldKept`] or [`Refusal::BudgetSpent`].
pub fn after_withdrawal(teardown: Teardown, charge: impl FnOnce() -> bool) -> Result<(), Refusal>
{
    if !teardown.quiet
    {
        return Err(Refusal::NotQuiet);
    }
    if !teardown.released
    {
        return Err(Refusal::HoldKept);
    }
    if !charge()
    {
        return Err(Refusal::BudgetSpent);
    }
    Ok(())
}

/// Whether `decl`, read from the drivers-directory entry a restart starts
/// from, declares the dead driver `name` on the record `record`: it carries
/// that name, the interrupt `interrupt` the dead driver declared, so the
/// caps devmgr kept for a platform record are the ones it needs, and it
/// matches the record as a drivers-directory declaration does (an IOMMU
/// family key not taken). An entry replaced by another driver, or by a
/// version that declares another interrupt, is not started in its place.
#[must_use]
pub fn same_driver(
    name: &DriverName,
    interrupt: Interrupt,
    decl: &DriverDecl,
    record: &RecordKeys<'_>,
) -> bool
{
    decl.name == *name
        && decl.interrupt == interrupt
        && decl_rank(decl, Source::DriversDir, record).is_some()
}

/// The outcome of a `DECLINE_RESTART` request ([`decline`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decline
{
    /// The driver at the ordinal is marked; its death is not restarted.
    Declined,
    /// The drivers directory is installed: restarts can happen, and the
    /// refusals they read are sealed.
    Sealed,
    /// The driver at the ordinal was withdrawn.
    Withdrawn,
    /// The class serves no driver at the ordinal.
    Absent,
}

/// Serve a `DECLINE_RESTART` of the driver at `ordinal` of the class
/// `served`: `mark` it, unless `sealed` (the drivers directory is
/// installed, so a restart may already have read the driver's refusal) or
/// the ordinal names no live driver.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`sealed` is data: whether devmgr holds its drivers directory"
)]
pub fn decline<T>(
    served: &mut Served<T>,
    ordinal: Option<usize>,
    sealed: bool,
    mark: impl FnOnce(&mut T),
) -> Decline
{
    if sealed
    {
        return Decline::Sealed;
    }
    let Some(ordinal) = ordinal
    else
    {
        return Decline::Absent;
    };
    if let Some(driver) = served.get_mut(ordinal)
    {
        mark(driver);
        return Decline::Declined;
    }
    match served.get(ordinal)
    {
        Lookup::Withdrawn => Decline::Withdrawn,
        Lookup::Live(_) | Lookup::Absent => Decline::Absent,
    }
}

#[cfg(test)]
mod tests
{
    use driver_binding::decl::{Declaration, Interrupt, Match, Reset, Tier, decode, encode};

    use super::*;
    use crate::binding::PciIdentity;

    const DIR: &[u8] = b"/services/drivers";
    const FAULT: u64 = EXIT_FAULT_BASE + 14;
    const KILLED: u64 = syscall_abi::EXIT_KILLED;

    #[test]
    fn an_entry_is_one_name_directly_in_the_directory()
    {
        assert_eq!(
            entry(DIR, b"/services/drivers/framebuffer"),
            Some(&b"framebuffer"[..])
        );
        assert_eq!(entry(DIR, b"/tests/drivers/test-fault"), None);
        assert_eq!(entry(DIR, b"/services/drivers"), None);
        assert_eq!(entry(DIR, b"/services/drivers/"), None);
        assert_eq!(entry(DIR, b"/services/drivers/virtio/blk"), None);
        // A sibling whose name extends the directory's is outside it.
        assert_eq!(entry(DIR, b"/services/drivers-old/serial"), None);
    }

    #[test]
    fn a_fault_or_a_kill_of_an_installed_driver_restarts_from_its_entry()
    {
        for reason in [FAULT, KILLED]
        {
            assert_eq!(
                restart_entry(reason, false, Some(DIR), b"/services/drivers/serial"),
                Ok(&b"serial"[..])
            );
        }
    }

    #[test]
    fn the_death_refusals_are_read_in_order()
    {
        let path = b"/services/drivers/serial";
        assert_eq!(
            restart_entry(0, true, None, b"/x"),
            Err(Refusal::Exited),
            "an exit of its own is not restarted, whatever else holds"
        );
        assert_eq!(
            restart_entry(EXIT_FAULT_BASE - 1, false, Some(DIR), path),
            Err(Refusal::Exited)
        );
        assert_eq!(
            restart_entry(FAULT, true, Some(DIR), path),
            Err(Refusal::Declined)
        );
        assert_eq!(
            restart_entry(FAULT, false, None, path),
            Err(Refusal::NoDriversDir)
        );
        assert_eq!(
            restart_entry(FAULT, false, Some(DIR), b"/tests/drivers/test-fault"),
            Err(Refusal::NotInstalled)
        );
    }

    #[test]
    fn a_device_not_quiet_or_a_kept_hold_refuses_without_charging_the_budget()
    {
        let done = Teardown {
            quiet: true,
            released: true,
        };
        let mut charged = false;
        let mut charge = || {
            charged = true;
            true
        };
        assert_eq!(
            after_withdrawal(
                Teardown {
                    quiet: false,
                    released: true,
                },
                &mut charge
            ),
            Err(Refusal::NotQuiet),
            "an IOMMU's block releases the hold of a device not confirmed quiet"
        );
        assert_eq!(
            after_withdrawal(
                Teardown {
                    quiet: false,
                    released: false,
                },
                &mut charge
            ),
            Err(Refusal::NotQuiet)
        );
        assert_eq!(
            after_withdrawal(
                Teardown {
                    quiet: true,
                    released: false,
                },
                &mut charge
            ),
            Err(Refusal::HoldKept)
        );
        assert!(!charged);
        assert_eq!(after_withdrawal(done, || false), Err(Refusal::BudgetSpent));
        assert_eq!(after_withdrawal(done, || true), Ok(()));
    }

    fn decl(name: &str, matches: &[Match<'_>], interrupt: Interrupt) -> DriverDecl
    {
        decode(
            encode(&Declaration {
                name,
                class: Some("c"),
                matches,
                instance_limit: None,
                interrupt,
                dma: false,
                dma_width: None,
                phys_access: false,
                reset: Reset::None,
                tier: Tier::Auxiliary,
            })
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn only_the_same_declaration_matching_the_record_from_the_directory_is_the_same_driver()
    {
        let record = RecordKeys {
            pci: Some(PciIdentity {
                vendor: 0x1AF4,
                device: 0x1044,
                class_code: 0x00FF_0000,
            }),
            ..RecordKeys::default()
        };
        let rng = Match::PciId {
            vendor: 0x1AF4,
            device: 0x1044,
        };
        let name = DriverName::literal_key("virtio-rng");
        let none = Interrupt::NONE;
        assert!(same_driver(
            &name,
            none,
            &decl("virtio-rng", &[rng], none),
            &record
        ));
        assert!(
            !same_driver(&name, none, &decl("other-rng", &[rng], none), &record),
            "an entry replaced by another driver"
        );
        assert!(
            !same_driver(
                &name,
                none,
                &decl("virtio-rng", &[rng], Interrupt::REQUIRED),
                &record
            ),
            "a version that declares another interrupt"
        );
        let blk = Match::PciId {
            vendor: 0x1AF4,
            device: 0x1042,
        };
        assert!(
            !same_driver(&name, none, &decl("virtio-rng", &[blk], none), &record),
            "a declaration that no longer matches"
        );
        assert!(
            !same_driver(
                &name,
                none,
                &decl("virtio-rng", &[Match::IommuFamily("dmar")], none),
                &RecordKeys {
                    iommu_family: Some(b"dmar"),
                    ..RecordKeys::default()
                }
            ),
            "an IOMMU family key is not taken from the drivers directory"
        );
    }

    /// A class serving `n` drivers, each recorded as `false` (not declined).
    fn class_of(n: usize) -> Served<bool>
    {
        let mut s = Served::new();
        s.try_reserve(n).unwrap();
        for badge in 1..=n as u64
        {
            s.push(badge, false).unwrap();
        }
        s
    }

    #[test]
    fn a_decline_marks_the_live_driver_at_its_ordinal()
    {
        let mut s = class_of(2);
        assert_eq!(
            decline(&mut s, Some(1), false, |d| *d = true),
            Decline::Declined
        );
        assert_eq!(s.get(0), Lookup::Live(&false));
        assert_eq!(s.get(1), Lookup::Live(&true));
    }

    #[test]
    fn a_decline_once_the_drivers_directory_is_installed_is_refused()
    {
        let mut s = class_of(1);
        assert_eq!(
            decline(&mut s, Some(0), true, |_| panic!(
                "a sealed decline marks nothing"
            )),
            Decline::Sealed
        );
        assert_eq!(s.get(0), Lookup::Live(&false));
    }

    #[test]
    fn a_decline_of_a_withdrawn_or_absent_ordinal_marks_nothing()
    {
        let mut s = class_of(2);
        // Ordinal 1 is the driver of badge 2.
        assert_eq!(s.withdraw(2), Some(false));
        let never = |_: &mut bool| panic!("nothing to mark");
        assert_eq!(
            decline(&mut s, Some(0), false, |d| *d = true),
            Decline::Declined
        );
        assert_eq!(decline(&mut s, Some(1), false, never), Decline::Withdrawn);
        assert_eq!(decline(&mut s, Some(2), false, never), Decline::Absent);
        assert_eq!(decline(&mut s, None, false, never), Decline::Absent);
    }
}
