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
//!
//! A create procmgr refuses with an error a later create can outlive is
//! retried, for a start and a restart alike ([`create_retryable`]): after
//! the delays [`retry_delay_ms`] gives, at most [`CREATE_RETRY_LIMIT`]
//! times, each pending retry held in [`Retries`] until it is due.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::fmt;

use driver_binding::decl::{DriverDecl, DriverName, Interrupt};
use ipc::procmgr_errors;
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

/// A served driver's end as devmgr takes it: the exit reason of the death
/// post that reported it, and procmgr's `QUERY_PROCESS` answer for the
/// driver's process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Death
{
    /// The reason the death post carries.
    pub posted: u64,
    /// procmgr's `QUERY_PROCESS` answer for the driver's process: word 0,
    /// the state, and word 1, the reason; `None` when devmgr holds no process
    /// handle of the driver, or the call failed or was refused.
    pub answer: Option<(u64, u64)>,
}

impl Death
{
    /// The exit reason devmgr decides on: the one procmgr gives the process
    /// when it answers `EXITED`, else the post's
    /// (`ipc::procmgr_process_state::process_reason`). The post can be the
    /// end of the driver's main thread alone, which is the process's end only
    /// when it is the first terminal end of any of its threads
    /// (`docs/process-lifecycle.md` § Exit reason): a main thread's
    /// `sys_thread_exit` posts 0 to devmgr's binding on it, and a fault of
    /// another thread before procmgr reads the process's end is the process's
    /// reason.
    #[must_use]
    pub fn reason(self) -> u64
    {
        ipc::procmgr_process_state::process_reason(self.answer, self.posted)
    }
}

/// When devmgr takes the death of a served driver installed at `path`,
/// `death`: the drivers-directory entry it restarts from, or
/// why it does not restart. `declined` is whether its consumer declined its
/// restart; `drivers_dir` is the drivers directory's path, `None` before
/// `SET_DRIVERS_DIR`.
///
/// # Errors
/// The [`Refusal`], checked in this order: an exit of its own (a reason,
/// [`Death::reason`], below `EXIT_FAULT_BASE`; a fault or a kill restarts),
/// the consumer's refusal, no drivers directory, a path outside it.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`declined` is data: the mark `DECLINE_RESTART` left on the dead driver"
)]
pub fn restart_entry<'a>(
    death: Death,
    declined: bool,
    drivers_dir: Option<&[u8]>,
    path: &'a [u8],
) -> Result<&'a [u8], Refusal>
{
    if death.reason() < EXIT_FAULT_BASE
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

/// Retries devmgr makes of one driver start whose create procmgr refuses
/// with an error a later create can outlive ([`create_retryable`]), before
/// it gives the start up (services/devmgr/docs/responsibilities.md § Create
/// retry). With the delays of [`retry_delay_ms`] the retries span 63 s, the
/// order of svcmgr's memory wait (`MEMORY_RETRY_LIMIT` retries a second
/// apart) at a tenth of its attempts, and past the root filesystem's stalls
/// of #1363, each of whose refusals itself takes procmgr's file-call timeout.
pub const CREATE_RETRY_LIMIT: u32 = 6;

/// The delay before a start's first create retry, in milliseconds; each
/// later retry waits twice the one before it ([`retry_delay_ms`]).
pub const CREATE_RETRY_FIRST_MS: u64 = 1000;

/// Whether procmgr's refusal `label` of a driver's create is one a later
/// create can outlive, so devmgr retries it: `IO_ERROR`, the binary's
/// file not opened or read (the file system stalled or refused), and
/// `OUT_OF_MEMORY`, memory short for the child or procmgr. Every other
/// refusal (a signature refused, an ELF or argument rejected, a mapping or
/// derivation failed, the argv and env still mapped) holds for any later
/// create of the same binary, and is final. A label is a reply procmgr gave,
/// so nothing was created; a failed call is no refusal, and is never retried.
#[must_use]
pub fn create_retryable(label: u64) -> bool
{
    matches!(
        label,
        procmgr_errors::IO_ERROR | procmgr_errors::OUT_OF_MEMORY
    )
}

/// The delay before create retry `retry` of a start, counted from 1, in
/// milliseconds: [`CREATE_RETRY_FIRST_MS`], doubled for each retry before
/// it. `None` past [`CREATE_RETRY_LIMIT`] (or for 0): the start is given up.
#[must_use]
pub fn retry_delay_ms(retry: u32) -> Option<u64>
{
    let doublings = retry.checked_sub(1)?;
    if retry > CREATE_RETRY_LIMIT
    {
        return None;
    }
    CREATE_RETRY_FIRST_MS.checked_shl(doublings)
}

/// The create retries pending, each with the monotonic time, in
/// nanoseconds, it falls due at. A record has at most one start pending, so
/// the list holds at most one retry per device record.
#[derive(Debug)]
pub struct Retries<T>
{
    pending: Vec<(u64, T)>,
}

impl<T> Default for Retries<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> Retries<T>
{
    /// No retry pending.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            pending: Vec::new(),
        }
    }

    /// Hold `retry`, due at `due_ns`.
    ///
    /// # Errors
    /// The allocation error, `retry` handed back, when the list cannot grow.
    pub fn push(&mut self, due_ns: u64, retry: T) -> Result<(), (TryReserveError, T)>
    {
        if let Err(e) = self.pending.try_reserve(1)
        {
            return Err((e, retry));
        }
        self.pending.push((due_ns, retry));
        Ok(())
    }

    /// Move every retry `other` holds into this list, `other` left empty.
    ///
    /// # Errors
    /// The allocation error when the list cannot grow by them; both lists are
    /// then as they were.
    pub fn append(&mut self, other: &mut Self) -> Result<(), TryReserveError>
    {
        self.pending.try_reserve(other.pending.len())?;
        self.pending.append(&mut other.pending);
        Ok(())
    }

    /// The earliest time a retry falls due at; `None` with none pending.
    #[must_use]
    pub fn next_due(&self) -> Option<u64>
    {
        self.pending.iter().map(|&(due, _)| due).min()
    }

    /// How long a wait from `now_ns` may last before the earliest retry
    /// falls due, in whole milliseconds rounded up, so the wait ends no
    /// earlier than the retry is due: `Some(0)` when one is due already,
    /// `None` with none pending.
    #[must_use]
    pub fn wait_ms(&self, now_ns: u64) -> Option<u64>
    {
        self.next_due()
            .map(|due| due.saturating_sub(now_ns).div_ceil(1_000_000))
    }

    /// Take the retry due earliest, when it is due at `now_ns`; ties in the
    /// order they were held.
    pub fn take_due(&mut self, now_ns: u64) -> Option<T>
    {
        let (at, _) = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, (due, _))| *due <= now_ns)
            .min_by_key(|(_, (due, _))| *due)?;
        Some(self.pending.remove(at).1)
    }

    /// Take every retry held, due or not.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_
    {
        self.pending.drain(..).map(|(_, retry)| retry)
    }

    /// Whether no retry is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.pending.is_empty()
    }
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

    /// A death whose post carries `reason` and whose query failed.
    fn posted(reason: u64) -> Death
    {
        Death {
            posted: reason,
            answer: None,
        }
    }

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
                restart_entry(
                    posted(reason),
                    false,
                    Some(DIR),
                    b"/services/drivers/serial"
                ),
                Ok(&b"serial"[..])
            );
        }
    }

    #[test]
    fn the_death_refusals_are_read_in_order()
    {
        let path = b"/services/drivers/serial";
        assert_eq!(
            restart_entry(posted(0), true, None, b"/x"),
            Err(Refusal::Exited),
            "an exit of its own is not restarted, whatever else holds"
        );
        assert_eq!(
            restart_entry(posted(EXIT_FAULT_BASE - 1), false, Some(DIR), path),
            Err(Refusal::Exited)
        );
        assert_eq!(
            restart_entry(posted(FAULT), true, Some(DIR), path),
            Err(Refusal::Declined)
        );
        assert_eq!(
            restart_entry(posted(FAULT), false, None, path),
            Err(Refusal::NoDriversDir)
        );
        assert_eq!(
            restart_entry(
                posted(FAULT),
                false,
                Some(DIR),
                b"/tests/drivers/test-fault"
            ),
            Err(Refusal::NotInstalled)
        );
    }

    #[test]
    fn the_restart_is_decided_on_the_reason_procmgr_gives_the_process()
    {
        use ipc::procmgr_process_state::{ALIVE, CREATED, EXITED, UNKNOWN};

        let path = b"/services/drivers/serial";
        // The main thread's sys_thread_exit posted 0; another thread's fault
        // ended the process before procmgr read its end.
        let worker_fault = Death {
            posted: 0,
            answer: Some((EXITED, FAULT)),
        };
        assert_eq!(worker_fault.reason(), FAULT);
        assert_eq!(
            restart_entry(worker_fault, false, Some(DIR), path),
            Ok(&b"serial"[..])
        );
        // procmgr gives the process an exit of its own over a posted fault.
        let exited = Death {
            posted: FAULT,
            answer: Some((EXITED, 0)),
        };
        assert_eq!(
            restart_entry(exited, false, Some(DIR), path),
            Err(Refusal::Exited)
        );
        // No EXITED answer, or no answer: the post's reason decides.
        for answer in [
            None,
            Some((ALIVE, FAULT)),
            Some((CREATED, FAULT)),
            Some((UNKNOWN, FAULT)),
        ]
        {
            let death = Death { posted: 0, answer };
            assert_eq!(death.reason(), 0);
            assert_eq!(
                restart_entry(death, false, Some(DIR), path),
                Err(Refusal::Exited)
            );
            let death = Death {
                posted: FAULT,
                answer,
            };
            assert_eq!(
                restart_entry(death, false, Some(DIR), path),
                Ok(&b"serial"[..])
            );
        }
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

    #[test]
    fn only_a_refusal_a_later_create_can_outlive_is_retried()
    {
        use ipc::procmgr_errors as e;
        assert!(create_retryable(e::IO_ERROR));
        assert!(create_retryable(e::OUT_OF_MEMORY));
        for label in [
            e::SUCCESS,
            e::INVALID_ELF,
            e::THREAD_CONFIGURE_FAILED,
            e::INVALID_BADGE,
            e::ALREADY_STARTED,
            e::THREAD_START_FAILED,
            e::INVALID_ARGUMENT,
            e::FILE_NOT_FOUND,
            e::MAP_FAILED,
            e::INSUFFICIENT_RIGHTS,
            e::UNAUTHORIZED,
            e::ARGV_ENV_STILL_MAPPED,
            e::NOT_ATTACHABLE,
            e::CRASH_SERVICE_PRESENT,
            e::THREAD_LIMIT,
            e::SIGNATURE_REFUSED,
            e::END_QUEUE_PRESENT,
            e::UNKNOWN_OPCODE,
        ]
        {
            assert!(!create_retryable(label), "label {label:#x} is final");
        }
    }

    #[test]
    fn the_retries_double_from_a_second_and_stop_at_the_limit()
    {
        let delays: Vec<u64> = (1..=CREATE_RETRY_LIMIT)
            .map(|retry| retry_delay_ms(retry).unwrap())
            .collect();
        assert_eq!(delays, [1000, 2000, 4000, 8000, 16_000, 32_000]);
        assert_eq!(delays.iter().sum::<u64>(), 63_000);
        assert_eq!(retry_delay_ms(CREATE_RETRY_LIMIT + 1), None, "given up");
        assert_eq!(retry_delay_ms(0), None);
        assert_eq!(retry_delay_ms(u32::MAX), None);
    }

    #[test]
    fn a_retry_is_taken_only_once_due_and_the_earliest_first()
    {
        let mut retries = Retries::new();
        assert_eq!(retries.wait_ms(0), None, "no retry: an untimed wait");
        assert_eq!(retries.take_due(u64::MAX), None);
        retries.push(3_000_000_000, 'b').unwrap();
        retries.push(1_000_000_000, 'a').unwrap();
        retries.push(3_000_000_000, 'c').unwrap();
        assert_eq!(retries.next_due(), Some(1_000_000_000));
        assert_eq!(retries.wait_ms(0), Some(1000));
        // Rounded up, so the wait does not end before the retry is due.
        assert_eq!(retries.wait_ms(999_999_999), Some(1));
        assert_eq!(retries.take_due(999_999_999), None, "not yet due");
        assert_eq!(retries.take_due(1_000_000_000), Some('a'));
        assert_eq!(retries.wait_ms(4_000_000_000), Some(0), "overdue: no wait");
        assert_eq!(retries.take_due(2_999_999_999), None);
        assert_eq!(
            retries.take_due(5_000_000_000),
            Some('b'),
            "ties in push order"
        );
        assert_eq!(retries.take_due(5_000_000_000), Some('c'));
        assert!(retries.is_empty());
    }

    #[test]
    fn appended_retries_join_the_list_and_drain_whole()
    {
        let mut held = Retries::new();
        held.push(5, 1).unwrap();
        let mut batch = Retries::new();
        batch.push(2, 2).unwrap();
        held.append(&mut batch).unwrap();
        assert!(batch.is_empty());
        assert_eq!(held.take_due(10), Some(2));
        held.push(1, 3).unwrap();
        let mut left: Vec<i32> = held.drain().collect();
        left.sort_unstable();
        assert_eq!(left, [1, 3]);
        assert!(held.is_empty());
    }
}
