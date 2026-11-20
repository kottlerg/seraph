// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/iommu_restart.rs

//! devmgr's restart of the IOMMU driver: whether it starts the driver again
//! after a death, and the records it keeps to rebuild, under the new
//! instance, the translation the dead one served
//! (`docs/device-management.md` § IOMMU Driver Restart).
//!
//! devmgr records each domain the driver attached ([`Domains`]: its handle,
//! unit, requester ID and domain ID) and, on VT-d, the interrupt remapping
//! table it set up and each entry it wrote ([`Remaps`]). The new instance is
//! given the same handles and domain IDs, so the records devmgr keeps by
//! handle (`dma::DmaTable`) stand unchanged, and the units' caches, tagged
//! by domain ID, hold no translation of another domain in the interval
//! between the first entry the commit swaps and the invalidation that ends
//! it. A dead instance's DMA hold is released only once a new instance has
//! committed its tables ([`Holds`]): until then the units may walk the dead
//! instance's pages. How one device's replay ends ([`replay_device`]): its
//! domain rebuilt, absent from the new tables, or attached and not blocked
//! again, which ends the attempt, is decided here over the calls devmgr's
//! control thread makes on the new instance ([`ReplayCalls`]).

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use syscall_abi::EXIT_FAULT_BASE;

/// Why the IOMMU driver is not restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// It exited with a code of its own: it decided to stop serving.
    Exited,
    /// devmgr does not hold what a restart needs: the driver's image, its
    /// units' register caps and anchors.
    NotKept,
    /// Its restart budget for the window is spent.
    BudgetSpent,
}

impl fmt::Display for Refusal
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(match self
        {
            Self::Exited => "it exited",
            Self::NotKept => "devmgr does not hold what its restart needs",
            Self::BudgetSpent => "its restart budget for this window is spent",
        })
    }
}

/// Whether the death of the IOMMU driver, with exit reason `reason`, may be
/// followed by a restart: a fault or a kill (`EXIT_FAULT_BASE` and above)
/// may, an exit of its own may not.
///
/// # Errors
/// [`Refusal::Exited`].
pub fn after_death(reason: u64) -> Result<(), Refusal>
{
    if reason < EXIT_FAULT_BASE
    {
        return Err(Refusal::Exited);
    }
    Ok(())
}

/// Whether a restart attempt starts: devmgr holds what it needs (`kept`),
/// and `charge`, which charges one restart to the driver's budget and
/// returns whether the budget had room, succeeds. `charge` is called only
/// when devmgr holds what the restart needs.
///
/// # Errors
/// [`Refusal::NotKept`] or [`Refusal::BudgetSpent`].
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`kept` is data: whether devmgr's restart records are present"
)]
pub fn attempt(kept: bool, charge: impl FnOnce() -> bool) -> Result<(), Refusal>
{
    if !kept
    {
        return Err(Refusal::NotKept);
    }
    if !charge()
    {
        return Err(Refusal::BudgetSpent);
    }
    Ok(())
}

/// One domain the IOMMU driver attached: a function of one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain
{
    /// The handle `ATTACH` returned, which every later request names.
    pub handle: u64,
    /// The unit's index in the driver.
    pub unit: usize,
    /// The function's requester ID (`ipc::iommu_labels::requester_id`).
    pub rid: u64,
    /// The domain ID its translations are tagged with on the unit.
    pub did: u64,
}

/// The domains the IOMMU driver holds, by handle.
#[derive(Debug, Default)]
pub struct Domains
{
    domains: Vec<Domain>,
}

impl Domains
{
    /// No domain.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            domains: Vec::new(),
        }
    }

    /// Record `domain`, replacing a domain recorded under its handle.
    ///
    /// # Errors
    /// The record cannot grow; nothing changes.
    pub fn record(&mut self, domain: Domain) -> Result<(), alloc::collections::TryReserveError>
    {
        if let Some(d) = self.domains.iter_mut().find(|d| d.handle == domain.handle)
        {
            *d = domain;
            return Ok(());
        }
        self.domains.try_reserve(1)?;
        self.domains.push(domain);
        Ok(())
    }

    /// Settle the ledger after the replay of the device whose domain is
    /// `handle` ended in `replay`: a domain absent from the restarted
    /// instance's tables is forgotten, so a withdrawal finds its function
    /// blocked and a later restart does not replay it.
    pub fn settle(&mut self, handle: u64, replay: Replay)
    {
        if matches!(replay, Replay::Absent(_))
        {
            self.forget(handle);
        }
    }

    /// Forget the domain `handle`, blocked or never attached.
    pub fn forget(&mut self, handle: u64)
    {
        self.domains.retain(|d| d.handle != handle);
    }

    /// The domain recorded under `handle`.
    #[must_use]
    pub fn get(&self, handle: u64) -> Option<Domain>
    {
        self.domains.iter().find(|d| d.handle == handle).copied()
    }
}

/// The calls a device's replay makes on a restarted instance of the IOMMU
/// driver; devmgr's control thread implements them over the instance's
/// endpoint.
pub trait ReplayCalls
{
    /// `ATTACH` the function of `domain` on its unit, naming its handle and
    /// domain ID; the handle and domain ID the instance replied.
    ///
    /// # Errors
    /// The instance's error label.
    fn attach(&mut self, domain: &Domain) -> Result<(u64, u64), u64>;

    /// Install the device's reserved ranges, interrupt files and mappings in
    /// the attached domain `domain` (`MAP_RESERVED`, `MAP_MSI`, `MAP`); the
    /// mappings installed.
    ///
    /// # Errors
    /// The first refusal's error label.
    fn fill(&mut self, domain: &Domain) -> Result<usize, u64>;

    /// `BLOCK` the domain `handle`; whether the instance accepted it.
    fn block(&mut self, handle: u64) -> bool;
}

/// What the replay of one confined device into a restarted instance left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay
{
    /// Its domain is rebuilt, with this many mappings.
    Rebuilt(usize),
    /// It was refused, with this error label, and its domain is absent from
    /// the instance's staged tables: either the `ATTACH` was refused or the
    /// domain was blocked again, so the units block the device from the
    /// commit on. devmgr forgets the domain ([`Domains::settle`]) and
    /// withdraws the device's driver.
    Absent(u64),
    /// A step after the `ATTACH` was refused and so was the `BLOCK` that
    /// would undo it: the staged tables hold the domain with part of its
    /// mappings, so the attempt must not commit.
    Unblocked,
}

/// Replay one confined device, whose recorded domain is `domain` (`None`
/// when devmgr holds no record of it), through `calls`: `ATTACH` it under
/// its recorded handle and domain ID, then install what it may reach. A
/// refusal after the `ATTACH`, or a reply naming another handle or domain
/// ID, blocks the domain the instance attached, so the device is absent from
/// the staged tables whichever step was refused.
pub fn replay_device(domain: Option<Domain>, calls: &mut impl ReplayCalls) -> Replay
{
    use ipc::iommu_errors::INVALID_REQUEST;
    let Some(domain) = domain
    else
    {
        return Replay::Absent(INVALID_REQUEST);
    };
    let (handle, did) = match calls.attach(&domain)
    {
        Ok(reply) => reply,
        Err(code) => return Replay::Absent(code),
    };
    let refused = if handle == domain.handle && did == domain.did
    {
        match calls.fill(&domain)
        {
            Ok(mappings) => return Replay::Rebuilt(mappings),
            Err(code) => code,
        }
    }
    else
    {
        INVALID_REQUEST
    };
    if calls.block(handle)
    {
        Replay::Absent(refused)
    }
    else
    {
        Replay::Unblocked
    }
}

/// One interrupt remapping entry devmgr had the driver write
/// (`iommu_labels::REMAP_SET`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemapEntry
{
    /// The entry's handle in the table.
    pub handle: u16,
    /// The interrupt controller ID of the CPU it delivers to.
    pub apic_id: u32,
    /// The vector it delivers.
    pub vector: u8,
    /// Whether it is level-triggered.
    pub level: bool,
    /// The source ID of the one requester it admits.
    pub source: u16,
}

/// The interrupt remapping table every VT-d unit shares: devmgr's Memory cap
/// on it, which devmgr keeps for the boot, its entries, and whether its
/// destinations are 32-bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemapTable
{
    /// devmgr's cap on the table's pages.
    pub cap: u64,
    /// The table's entries (`iommu_labels::REMAP_SETUP`).
    pub entries: u64,
    /// Whether the driver was asked for 32-bit destinations.
    pub extended: bool,
}

/// The interrupt remapping devmgr set up through the driver: the table and
/// each entry written and not cleared since.
#[derive(Debug, Default)]
pub struct Remaps
{
    table: Option<RemapTable>,
    entries: Vec<RemapEntry>,
}

impl Remaps
{
    /// No table and no entry.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            table: None,
            entries: Vec::new(),
        }
    }

    /// Record the table remapping was turned on with.
    pub fn set_table(&mut self, table: RemapTable)
    {
        self.table = Some(table);
    }

    /// Forget the table and every entry, remapping having been turned off;
    /// the table's cap, for the caller to delete.
    pub fn take_table(&mut self) -> Option<u64>
    {
        self.entries.clear();
        self.table.take().map(|t| t.cap)
    }

    /// The table remapping is on with.
    #[must_use]
    pub fn table(&self) -> Option<RemapTable>
    {
        self.table
    }

    /// Record `entry`, replacing what its handle held.
    ///
    /// # Errors
    /// The record cannot grow; nothing changes.
    pub fn set(&mut self, entry: RemapEntry) -> Result<(), alloc::collections::TryReserveError>
    {
        if let Some(e) = self.entries.iter_mut().find(|e| e.handle == entry.handle)
        {
            *e = entry;
            return Ok(());
        }
        self.entries.try_reserve(1)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Forget the entry `handle`, cleared.
    pub fn clear(&mut self, handle: u16)
    {
        self.entries.retain(|e| e.handle != handle);
    }

    /// Every entry written and not cleared.
    #[must_use]
    pub fn entries(&self) -> &[RemapEntry]
    {
        &self.entries
    }
}

/// The DMA holds of the IOMMU driver's dead instances: each instance's pages
/// may be walked by a unit until a later instance has committed its own
/// tables, so every dead instance's hold is released at the first commit
/// after its death, and none before.
#[derive(Debug)]
pub struct Holds<T>
{
    dead: Vec<T>,
}

impl<T> Default for Holds<T>
{
    fn default() -> Self
    {
        Self { dead: Vec::new() }
    }
}

impl<T> Holds<T>
{
    /// Keep the hold of an instance that died, or one devmgr destroyed after
    /// it may have touched a unit.
    ///
    /// # Errors
    /// The record cannot grow: `hold` is handed back, for the caller to keep
    /// for the boot.
    pub fn keep(&mut self, hold: T) -> Result<(), T>
    {
        if self.dead.try_reserve(1).is_err()
        {
            return Err(hold);
        }
        self.dead.push(hold);
        Ok(())
    }

    /// A new instance has committed its tables: every hold kept so far, for
    /// the caller to release.
    pub fn committed(&mut self) -> Vec<T>
    {
        core::mem::take(&mut self.dead)
    }

    /// How many holds are kept.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.dead.len()
    }

    /// Whether no hold is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.dead.is_empty()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A fake restarted instance: the replies it gives and the calls it saw.
    struct Fake
    {
        attach: Result<(u64, u64), u64>,
        fill: Result<usize, u64>,
        block: bool,
        filled: bool,
        blocked: Vec<u64>,
    }

    impl Fake
    {
        fn serving(domain: Domain) -> Self
        {
            Self {
                attach: Ok((domain.handle, domain.did)),
                fill: Ok(3),
                block: true,
                filled: false,
                blocked: Vec::new(),
            }
        }
    }

    impl ReplayCalls for Fake
    {
        fn attach(&mut self, _domain: &Domain) -> Result<(u64, u64), u64>
        {
            self.attach
        }

        fn fill(&mut self, _domain: &Domain) -> Result<usize, u64>
        {
            self.filled = true;
            self.fill
        }

        fn block(&mut self, handle: u64) -> bool
        {
            self.blocked.push(handle);
            self.block
        }
    }

    const REPLAYED: Domain = Domain {
        handle: 7,
        unit: 0,
        rid: 0x18,
        did: 3,
    };
    const OUT_OF_RESOURCES: u64 = ipc::iommu_errors::OUT_OF_RESOURCES;

    fn ledger() -> Domains
    {
        let mut domains = Domains::new();
        domains.record(REPLAYED).unwrap();
        domains
    }

    #[test]
    fn a_replayed_device_is_rebuilt_and_kept_in_the_ledger()
    {
        let mut fake = Fake::serving(REPLAYED);
        let replay = replay_device(Some(REPLAYED), &mut fake);
        assert_eq!(replay, Replay::Rebuilt(3));
        assert_eq!(fake.blocked, []);
        let mut domains = ledger();
        domains.settle(REPLAYED.handle, replay);
        assert_eq!(domains.get(REPLAYED.handle), Some(REPLAYED));
    }

    #[test]
    fn a_refused_attach_leaves_the_device_absent_and_forgotten()
    {
        let mut fake = Fake::serving(REPLAYED);
        fake.attach = Err(OUT_OF_RESOURCES);
        let replay = replay_device(Some(REPLAYED), &mut fake);
        assert_eq!(replay, Replay::Absent(OUT_OF_RESOURCES));
        assert!(
            !fake.filled,
            "nothing is installed in a domain not attached"
        );
        assert_eq!(fake.blocked, [], "a domain not attached needs no block");
        let mut domains = ledger();
        domains.settle(REPLAYED.handle, replay);
        assert_eq!(domains.get(REPLAYED.handle), None);
    }

    #[test]
    fn a_refusal_after_the_attach_blocks_the_domain_before_the_commit()
    {
        let mut fake = Fake::serving(REPLAYED);
        fake.fill = Err(OUT_OF_RESOURCES);
        let replay = replay_device(Some(REPLAYED), &mut fake);
        assert_eq!(replay, Replay::Absent(OUT_OF_RESOURCES));
        assert_eq!(fake.blocked, [REPLAYED.handle]);
        let mut domains = ledger();
        domains.settle(REPLAYED.handle, replay);
        assert_eq!(domains.get(REPLAYED.handle), None);
    }

    #[test]
    fn an_attach_naming_another_domain_is_blocked_again()
    {
        let mut fake = Fake::serving(REPLAYED);
        fake.attach = Ok((REPLAYED.handle + 1, REPLAYED.did));
        let replay = replay_device(Some(REPLAYED), &mut fake);
        assert_eq!(replay, Replay::Absent(ipc::iommu_errors::INVALID_REQUEST));
        assert!(
            !fake.filled,
            "nothing is installed in a domain the replay did not ask for"
        );
        assert_eq!(fake.blocked, [REPLAYED.handle + 1]);
    }

    #[test]
    fn a_refused_block_after_a_refusal_ends_the_attempt_and_keeps_the_ledger()
    {
        let mut fake = Fake::serving(REPLAYED);
        fake.fill = Err(OUT_OF_RESOURCES);
        fake.block = false;
        let replay = replay_device(Some(REPLAYED), &mut fake);
        assert_eq!(replay, Replay::Unblocked);
        let mut domains = ledger();
        domains.settle(REPLAYED.handle, replay);
        assert_eq!(domains.get(REPLAYED.handle), Some(REPLAYED));
    }

    #[test]
    fn a_device_with_no_recorded_domain_makes_no_call()
    {
        let mut fake = Fake::serving(REPLAYED);
        fake.attach = Err(OUT_OF_RESOURCES);
        assert_eq!(
            replay_device(None, &mut fake),
            Replay::Absent(ipc::iommu_errors::INVALID_REQUEST)
        );
        assert!(!fake.filled);
        assert_eq!(fake.blocked, []);
    }

    #[test]
    fn only_a_fault_or_a_kill_is_followed_by_a_restart()
    {
        assert_eq!(after_death(0), Err(Refusal::Exited));
        assert_eq!(after_death(EXIT_FAULT_BASE - 1), Err(Refusal::Exited));
        assert_eq!(after_death(EXIT_FAULT_BASE), Ok(()));
        assert_eq!(after_death(u64::MAX), Ok(()));
    }

    #[test]
    fn an_attempt_needs_the_records_and_is_charged_only_then()
    {
        let mut charged = false;
        assert_eq!(
            attempt(false, || {
                charged = true;
                true
            }),
            Err(Refusal::NotKept)
        );
        assert!(!charged, "a refused attempt charges nothing");
        assert_eq!(attempt(true, || false), Err(Refusal::BudgetSpent));
        assert_eq!(attempt(true, || true), Ok(()));
    }

    #[test]
    fn a_domain_is_recorded_once_per_handle_and_forgotten_by_handle()
    {
        let mut domains = Domains::new();
        let first = Domain {
            handle: 1,
            unit: 0,
            rid: 0x20,
            did: 1,
        };
        domains.record(first).unwrap();
        domains
            .record(Domain {
                handle: 2,
                unit: 1,
                rid: 0x28,
                did: 1,
            })
            .unwrap();
        let replaced = Domain { did: 7, ..first };
        domains.record(replaced).unwrap();
        assert_eq!(domains.get(1), Some(replaced));
        domains.forget(1);
        assert_eq!(domains.get(1), None);
        assert_eq!(domains.get(2).map(|d| d.unit), Some(1));
    }

    #[test]
    fn a_remapping_entry_is_replaced_by_handle_and_turning_remapping_off_forgets_every_one()
    {
        let mut remaps = Remaps::new();
        let entry = RemapEntry {
            handle: 3,
            apic_id: 0,
            vector: 0x40,
            level: false,
            source: 0x20,
        };
        remaps.set_table(RemapTable {
            cap: 9,
            entries: 256,
            extended: true,
        });
        remaps.set(entry).unwrap();
        remaps
            .set(RemapEntry {
                vector: 0x41,
                ..entry
            })
            .unwrap();
        remaps.set(RemapEntry { handle: 4, ..entry }).unwrap();
        assert_eq!(remaps.entries().len(), 2);
        assert_eq!(remaps.entries()[0].vector, 0x41);
        remaps.clear(4);
        assert_eq!(remaps.entries().len(), 1);
        assert_eq!(remaps.take_table(), Some(9));
        assert_eq!(remaps.entries(), []);
        assert_eq!(remaps.table(), None);
    }

    // Defect caught: a hold released before a later instance commits frees
    // pages a unit still walks.
    #[test]
    fn every_dead_hold_is_released_at_the_first_commit_after_it_and_none_before()
    {
        let mut holds = Holds::default();
        holds.keep(1).unwrap();
        // A restart attempt that fails after it started keeps its own.
        holds.keep(2).unwrap();
        assert_eq!(holds.len(), 2);
        assert_eq!(holds.committed(), [1, 2]);
        assert!(holds.is_empty());
        holds.keep(3).unwrap();
        assert_eq!(holds.committed(), [3]);
    }
}
